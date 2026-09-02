package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/mon/dpop"
	"github.com/nokku-sh/mon/id"
	"github.com/nokku-sh/mon/tpm"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

const (
	urlHeader         = "Nokku-Api-Url"
	nonceRefreshAfter = 5 * time.Minute
)

var SignerSalt = []byte("nokku-cli")

// dpopAuth authenticates interactive (device) sessions: it sends the
// persisted session token with the "DPoP" scheme and binds every request to
// the CLI's signing key with a DPoP proof. It learns the server nonce from the
// DPoP-Nonce response header and retries once when the server reports a stale
// nonce (RFC 9449 section 8).
type dpopAuth struct {
	state   *state.State
	proofer *dpop.Proofer
	httpc   *http.Client

	mu        sync.Mutex
	nonce     string
	learnedAt time.Time
	serverURL string
}

func withDPoP(s *state.State, httpc *http.Client) (*dpopAuth, error) {
	auth := &dpopAuth{state: s, httpc: httpc}

	if !s.IsServiceAccount() {
		signer, err := tpm.NewSigner(tpm.SignerOptions{
			Salt:            SignerSalt,
			Store:           tpm.NewFileStore(paths.SignerStateFile()),
			MachineID:       id.MachineID,
			RequireTPM:      s.RequireTPM,
			RecoverIdentity: true,
		})
		if err != nil {
			return nil, err
		}
		auth.proofer, err = dpop.NewProofer(signer, dpop.ProoferOptions{})
		if err != nil {
			return nil, err
		}
	}
	return auth, nil
}

func (a *dpopAuth) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		switch {
		case a.interactive():
			a.refreshNonce(ctx)
			if err := a.sign(req.Header(), req.Spec().Procedure); err != nil {
				return nil, err
			}
			resp, err := next(ctx, req)
			if err != nil && a.learnNonce(err) {
				// Wipe the old DPoP header before signing again
				req.Header().Del("DPoP")
				if err = a.sign(req.Header(), req.Spec().Procedure); err != nil {
					return nil, err
				}
				return next(ctx, req)
			}
			return resp, err
		case a.state.IsServiceAccount():
			req.Header().Set("Authorization", "Bearer "+a.state.Token)
		}
		return next(ctx, req)
	}
}

func (a *dpopAuth) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		switch {
		case a.interactive():
			a.refreshNonce(ctx)
			_ = a.sign(conn.RequestHeader(), spec.Procedure)
		case a.state.IsServiceAccount():
			conn.RequestHeader().Set("Authorization", "Bearer "+a.state.Token)
		}
		return conn
	}
}

func (a *dpopAuth) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

// interactive reports whether the client is using a device session (not a
// service-account API key).
func (a *dpopAuth) interactive() bool {
	return !a.state.IsServiceAccount() && a.state.SessionToken != ""
}

// refreshNonce re-fetches the server nonce when the cached one is old
// enough to risk rejection. Best effort: on failure the cached nonce is
// kept, matching the pre-existing behavior.
func (a *dpopAuth) refreshNonce(ctx context.Context) {
	a.mu.Lock()
	learnedAt := a.learnedAt
	a.mu.Unlock()
	if time.Since(learnedAt) <= nonceRefreshAfter {
		return
	}
	nonce, serverURL, err := FetchNonce(ctx, a.httpc, a.state.APIURL)
	if err != nil {
		slog.Debug("dpop nonce prefetch failed, using cached nonce", "error", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if nonce != "" {
		a.nonce = nonce
		a.learnedAt = time.Now()
	}
	if serverURL != "" {
		a.serverURL = serverURL
	}
}

// sign sets the DPoP-bound token and DPoP proof on the request header.
func (a *dpopAuth) sign(header http.Header, procedure string) error {
	// RFC 9449: MUST use "DPoP" scheme for bound tokens
	header.Set("Authorization", "DPoP "+a.state.SessionToken)
	htu := a.htuBase() + procedure

	proof, err := a.proofer.Sign(
		http.MethodPost,
		htu,
		dpop.ATH(a.state.SessionToken),
		a.currentNonce(),
	)
	if err != nil {
		return connect.NewError(
			connect.CodeInternal,
			fmt.Errorf("failed to sign DPoP proof: %w", err),
		)
	}
	header.Set("DPoP", proof)
	return nil
}

// htuBase returns the URL proofs must bind to: the canonical API URL the
// server advertises when known, else the configured API URL.
func (a *dpopAuth) htuBase() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.serverURL != "" {
		return a.serverURL
	}
	return a.state.APIURL
}

// learnResponse records the nonce and canonical URL a raw HTTP response
// (the device-flow endpoints) advertised, if any. A learned nonce counts as
// fresh, so the next connect call skips the refresh.
func (a *dpopAuth) learnResponse(header http.Header) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n := header.Get("DPoP-Nonce"); n != "" {
		a.nonce = n
		a.learnedAt = time.Now()
	}
	if u := header.Get(urlHeader); u != "" {
		a.serverURL = u
	}
}

// learnNonce records a fresh nonce from a stale-nonce error response and
// reports whether the server advertised one (so the caller retries). The same
// response carries the canonical API URL, which is learned alongside.
func (a *dpopAuth) learnNonce(err error) bool {
	cerr, ok := errors.AsType[*connect.Error](err)
	if !ok || connect.CodeOf(err) != connect.CodeUnauthenticated {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	learned := false
	if n := cerr.Meta().Get("DPoP-Nonce"); n != "" {
		a.nonce = n
		learned = true
	}
	if u := cerr.Meta().Get(urlHeader); u != "" {
		a.serverURL = u
	}
	return learned
}

// learn records a nonce and canonical URL fetched out of band via FetchNonce.
func (a *dpopAuth) learn(nonce, serverURL string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if nonce != "" {
		a.nonce = nonce
		a.learnedAt = time.Now()
	}
	if serverURL != "" {
		a.serverURL = serverURL
	}
}

func (a *dpopAuth) currentNonce() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nonce
}

// FetchNonce bootstraps the DPoP nonce and the canonical API URL from the
// server before the first DPoP-protected request, avoiding a deliberate 401
// round-trip. The canonical URL is what proofs must bind to; baseURL is only
// where to reach the server.
func FetchNonce(
	ctx context.Context,
	httpc *http.Client,
	baseURL string,
) (nonce, apiURL string, err error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		strings.TrimRight(baseURL, "/")+"/auth/device/nonce",
		nil,
	)
	if err != nil {
		return "", "", err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Get("DPoP-Nonce"), resp.Header.Get(urlHeader), nil
}
