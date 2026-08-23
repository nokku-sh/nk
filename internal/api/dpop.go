package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kagi/dpop"

	"github.com/nokku-sh/nk/internal/state"
)

// dpopAuth authenticates interactive (device) sessions: it sends the
// persisted session token with the "DPoP" scheme and binds every request to
// the CLI's signing key with a DPoP proof. It learns the server nonce from the
// DPoP-Nonce response header and retries once when the server reports a stale
// nonce (RFC 9449 section 8).
//
// Service-account requests take the non-interactive path instead: their API
// key is a plain bearer token with no DPoP binding.
type dpopAuth struct {
	state   *state.State
	proofer *dpop.Proofer

	mu    sync.Mutex
	nonce string
}

// WithDPoP builds the interactive-session interceptor. baseURL is the API
// origin used to reconstruct each request's htu, matching the server's
// BaseURL configuration.
func WithDPoP(
	st *state.State,
	proofer *dpop.Proofer,
	initialNonce string,
) connect.Interceptor {
	return &dpopAuth{
		state:   st,
		proofer: proofer,
		nonce:   initialNonce,
	}
}

func (a *dpopAuth) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		switch {
		case a.interactive():
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

// sign sets the DPoP-bound token and DPoP proof on the request header.
func (a *dpopAuth) sign(header http.Header, procedure string) error {
	// RFC 9449: MUST use "DPoP" scheme for bound tokens
	header.Set("Authorization", "DPoP "+a.state.SessionToken)
	htu := a.state.APIURL + procedure

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

// learnNonce records a fresh nonce from a stale-nonce error response and
// reports whether the server advertised one (so the caller retries).
func (a *dpopAuth) learnNonce(err error) bool {
	var cerr *connect.Error
	if !errors.As(err, &cerr) || connect.CodeOf(err) != connect.CodeUnauthenticated {
		return false
	}
	if n := cerr.Meta().Get("DPoP-Nonce"); n != "" {
		a.mu.Lock()
		a.nonce = n
		a.mu.Unlock()
		return true
	}
	return false
}

func (a *dpopAuth) currentNonce() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nonce
}

// FetchNonce bootstraps the DPoP nonce from the server before the first
// DPoP-protected request, avoiding a deliberate 401 round-trip.
func FetchNonce(ctx context.Context, httpc *http.Client, baseURL string) (string, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		strings.TrimRight(baseURL, "/")+"/auth/nonce",
		nil,
	)
	if err != nil {
		return "", err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Get("DPoP-Nonce"), nil
}
