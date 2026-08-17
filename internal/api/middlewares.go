package api

import (
	"context"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	"github.com/cenkalti/backoff/v7"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nk/internal/state"
)

// withIdentityHeaders adds the client identity headers (version, hostname) to
// every request. Authentication headers (bearer token + DPoP proof, or the
// service-account API key) are added by the auth interceptors.
func withIdentityHeaders(st *state.State) connect.Interceptor {
	hostname, _ := os.Hostname()
	return &identityInterceptor{st: st, hostname: hostname}
}

type identityInterceptor struct {
	st       *state.State
	hostname string
}

func (a *identityInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		a.setHeader(req.Header())
		return next(ctx, req)
	}
}

func (a *identityInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		a.setHeader(conn.RequestHeader())
		return conn
	}
}

func (a *identityInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

func (a *identityInterceptor) setHeader(header http.Header) {
	if a.st.IsServiceAccount() {
		header.Set("Authorization", "Bearer "+a.st.Token)
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
