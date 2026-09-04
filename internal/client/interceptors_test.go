package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/state"
)

func TestWithRetryRetriesTransient(t *testing.T) {
	t.Parallel()
	calls := 0
	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		calls++
		if calls == 1 {
			return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("rate limited"))
		}
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	resp, err := withRetry()(next)(context.Background(), connect.NewRequest(&nokkuv1.User{}))
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 2, calls, "a transient failure must be retried")
}

func TestWithRetryFailsFastOnPermanent(t *testing.T) {
	t.Parallel()
	calls := 0
	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		calls++
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such target"))
	}

	_, err := withRetry()(next)(context.Background(), connect.NewRequest(&nokkuv1.User{}))
	require.Error(t, err)
	assert.Equal(t, 1, calls, "a permanent failure must not be retried")
}

func TestWithUA(t *testing.T) {
	t.Parallel()
	var ua string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ua = req.Header().Get("User-Agent")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	_, err := withUA().WrapUnary(next)(context.Background(), connect.NewRequest(&nokkuv1.User{}))
	require.NoError(t, err)
	assert.Equal(t, buildinfo.UserAgent("nk"), ua)
}

func TestWrapUnaryRetriesAfterStaleNonce(t *testing.T) {
	t.Parallel()
	st := &state.State{SessionToken: "sess-token", APIURL: "https://app.example.com"}
	a := &dpopAuth{
		state:     st,
		proofer:   newTestProofer(t),
		learnedAt: time.Now(), // fresh: skip the out-of-band nonce refresh
	}

	calls := 0
	var proofs []string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		calls++
		proofs = append(proofs, req.Header().Get("DPoP"))
		if calls == 1 {
			cerr := connect.NewError(connect.CodeUnauthenticated, errors.New("stale DPoP nonce"))
			cerr.Meta().Set("DPoP-Nonce", "nonce-2")
			return nil, cerr
		}
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	resp, err := a.WrapUnary(next)(context.Background(), connect.NewRequest(&nokkuv1.User{}))
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 2, calls, "a stale nonce must trigger exactly one re-sign and retry")
	require.Len(t, proofs, 2)
	assert.NotEqual(t, proofs[0], proofs[1], "the retry must carry a freshly signed proof")
}
