package client

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/cenkalti/backoff/v7"
	"github.com/mizuchilabs/kata/buildinfo"
)

// bearerAuth attaches the service-account API key and the client User-Agent.
type bearerAuth struct {
	token string
	ua    string
}

func newBearerAuth(token string) *bearerAuth {
	return &bearerAuth{token: token, ua: buildinfo.UserAgent("nk")}
}

func (a *bearerAuth) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		a.set(req.Header())
		return next(ctx, req)
	}
}

func (a *bearerAuth) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		a.set(conn.RequestHeader())
		return conn
	}
}

func (a *bearerAuth) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

func (a *bearerAuth) set(header http.Header) {
	header.Set("Authorization", "Bearer "+a.token)
	if a.ua != "" {
		header.Set("User-Agent", a.ua)
	}
}

// withRetry retries transient connect errors briefly. Permanent codes pass
// through so the CLI falls back to cached data fast.
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
				// A down backend must fail fast so commands fall back to
				// cached data.
				backoff.WithMaxElapsedTime(3*time.Second),
			)
		}
	}
}
