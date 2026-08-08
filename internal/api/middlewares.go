package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"net/http"
	"os"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/cenkalti/backoff/v7"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/tpm"
)

type auth struct {
	state    *state.State
	signer   tpm.Signer
	hostname string
}

func WithAuth(state *state.State, signer tpm.Signer) connect.Interceptor {
	a := &auth{state: state, signer: signer}
	if name, err := os.Hostname(); err == nil {
		a.hostname = name
	}
	return a
}

func (a *auth) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		a.setHeader(ctx, req.Header(), req.Spec().Procedure)
		return next(ctx, req)
	}
}

func (a *auth) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		a.setHeader(ctx, conn.RequestHeader(), spec.Procedure)
		return conn
	}
}

func (a *auth) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

func (a *auth) setHeader(ctx context.Context, header http.Header, procedure string) {
	if a.state.IsServiceAccount() {
		header.Set("Authorization", "Bearer "+a.state.Token)
	} else if a.signer != nil && a.state.GetDeviceID() != "" {
		challenge, err := a.challenge(ctx, a.state.GetDeviceID(), procedure)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to sign request: %v\n", err)
		} else {
			header.Set("Authorization", "Nokku "+challenge)
		}
	}
	// The device ID is always sent: the login stream uses it to register
	// the device's signing key, and challenge requests tie it to the
	// signed payload.
	if a.state.GetDeviceID() != "" {
		header.Set("Nokku-Client-Device-Id", a.state.GetDeviceID())
	}
	if buildinfo.Version != "" {
		header.Set("Nokku-Client-Version", buildinfo.Version)
	}
	if buildinfo.Commit != "" {
		header.Set("Nokku-Client-Commit", buildinfo.Commit)
	}
	if buildinfo.Date != "" {
		header.Set("Nokku-Client-Builddate", buildinfo.Date)
	}
	if a.hostname != "" {
		header.Set("Nokku-Client-Hostname", a.hostname)
	}
}

// challenge builds a signed request challenge of the form
//
//	<deviceID>:<unixSeconds>:<nonce>:<procedure>:<base64url(signature)>
//
// The signature covers everything up to and including the procedure, so a
// captured challenge cannot be replayed against a different RPC, and the
// backend rejects challenges older than its freshness window.
func (a *auth) challenge(ctx context.Context, deviceID, procedure string) (string, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := fmt.Sprintf("%s:%s:%s:%s", deviceID, ts, hex.EncodeToString(nonce), procedure)
	sig, err := a.signer.Sign(ctx, []byte(payload))
	if err != nil {
		return "", err
	}
	return payload + ":" + base64.RawURLEncoding.EncodeToString(sig), nil
}

func withRetry() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			ops := func() (connect.AnyResponse, error) {
				resp, err := next(ctx, req)
				if err == nil {
					return resp, nil
				}

				//nolint:exhaustive // retry on transient codes, permanent on everything else
				switch connect.CodeOf(err) {
				case connect.CodeAborted, connect.CodeResourceExhausted:
					return nil, err
				default:
					return nil, backoff.Permanent(err)
				}
			}

			b := backoff.NewExponentialBackOff()
			return backoff.Retry(
				ctx, ops,
				backoff.WithBackOff(b),
				backoff.WithMaxElapsedTime(10*time.Second),
			)
		}
	}
}
