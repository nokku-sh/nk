package client

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
)

func TestBearerAuthSetsHeader(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	var authz, ua string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		authz = req.Header().Get("Authorization")
		ua = req.Header().Get("User-Agent")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	_, err := newBearerAuth("nokku_sa_secret").
		WrapUnary(next)(context.Background(), connect.NewRequest(&nokkuv1.User{}))
	must.NoError(err)
	is.Equal("Bearer nokku_sa_secret", authz)
	is.NotEmpty(ua, "service-account requests must still identify the client")
}

func TestWithRetryRetriesTransientError(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	calls := 0
	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		calls++
		if calls < 2 {
			return nil, connect.NewError(connect.CodeAborted, errors.New("transient"))
		}
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	_, err := withRetry()(next)(context.Background(), connect.NewRequest(&nokkuv1.User{}))
	must.NoError(err)
	is.GreaterOrEqual(calls, 2, "a transient code must be retried")
}

func TestWithRetryDoesNotRetryPermanentError(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	calls := 0
	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		calls++
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad request"))
	}

	_, err := withRetry()(next)(context.Background(), connect.NewRequest(&nokkuv1.User{}))
	must.Error(err)
	is.Equal(1, calls, "a permanent code must not be retried")
}
