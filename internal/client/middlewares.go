package client

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/cenkalti/backoff/v7"
	"github.com/mizuchilabs/kata/buildinfo"
)

type uaInterceptor struct {
	ua string
}

func withUA() connect.Interceptor {
	return &uaInterceptor{ua: buildinfo.UserAgent("nk")}
}

func (a *uaInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("User-Agent", a.ua)
		return next(ctx, req)
	}
}

func (a *uaInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		conn.RequestHeader().Set("User-Agent", a.ua)
		return conn
	}
}

func (a *uaInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
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
				// Keep the retry budget small: a down backend must fail
				// fast so commands fall back to cached data quickly.
				backoff.WithMaxElapsedTime(3*time.Second),
			)
		}
	}
}
