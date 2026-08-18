package api

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/cenkalti/backoff/v7"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nk/internal/state"
)

// withClientHeaders sets a standard User-Agent and, for service accounts,
// the bearer token on every request. Interactive sessions carry their bearer
// token and DPoP proof via the dpopAuth interceptor instead.
func withClientHeaders(st *state.State) connect.Interceptor {
	return &clientHeadersInterceptor{st: st, userAgent: buildinfo.UserAgent("nk")}
}

type clientHeadersInterceptor struct {
	st        *state.State
	userAgent string
}

func (a *clientHeadersInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		a.setHeaders(req.Header())
		return next(ctx, req)
	}
}

func (a *clientHeadersInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		a.setHeaders(conn.RequestHeader())
		return conn
	}
}

func (a *clientHeadersInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

func (a *clientHeadersInterceptor) setHeaders(header http.Header) {
	header.Set("User-Agent", a.userAgent)
	if a.st.IsServiceAccount() {
		header.Set("Authorization", "Bearer "+a.st.Token)
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
