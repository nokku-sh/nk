package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/mon/dpop"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/state"
)

func newTestProofer(t *testing.T) *dpop.Proofer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p, err := dpop.NewProofer(key, dpop.ProoferOptions{})
	require.NoError(t, err)
	return p
}

func TestDPoPAuthInteractiveSignsRequest(t *testing.T) {
	t.Parallel()
	st := &state.State{
		SessionToken: "sess-token", APIURL: "https://app.example.com",
	}
	proofer := newTestProofer(t)

	var authz, proof string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		authz = req.Header().Get("Authorization")
		proof = req.Header().Get("DPoP")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	auth := dpopAuth{state: st, proofer: proofer, learnedAt: time.Now()}
	wrapped := auth.WrapUnary(next)
	req := connect.NewRequest(&nokkuv1.User{})
	_, err := wrapped(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "DPoP sess-token", authz)
	assert.NotEmpty(t, proof, "expected a DPoP proof header")
}

func TestDPoPAuthHTUHasNoDoubleSlash(t *testing.T) {
	t.Parallel()
	st := &state.State{
		SessionToken: "sess-token", APIURL: "https://app.example.com",
	}
	proofer := newTestProofer(t)

	a := &dpopAuth{state: st, proofer: proofer}
	header := http.Header{}
	a.sign(header, "/nokku.v1.UserService/Whoami")

	proof := header.Get("DPoP")
	require.NotEmpty(t, proof, "expected a DPoP proof header")

	var claims struct {
		HTU string `json:"htu"`
	}
	parseProofClaims(t, proof, &claims)
	assert.Equal(t, "https://app.example.com/nokku.v1.UserService/Whoami", claims.HTU)
}

func TestDPoPAuthSkipsServiceAccount(t *testing.T) {
	t.Parallel()
	st := &state.State{
		Token:  "nokku_sa_secret",
		APIURL: "https://app.example.com",
	}
	proofer := newTestProofer(t)

	var proof string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		proof = req.Header().Get("DPoP")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	auth := dpopAuth{state: st, proofer: proofer, nonce: "", serverURL: ""}
	wrapped := auth.WrapUnary(next)
	req := connect.NewRequest(&nokkuv1.User{})
	_, err := wrapped(context.Background(), req)
	require.NoError(t, err)
	assert.Empty(t, proof, "want empty DPoP for service accounts")
}

func TestDPoPAuthNoSessionNoHeaders(t *testing.T) {
	t.Parallel()
	st := &state.State{APIURL: "https://app.example.com"}
	proofer := newTestProofer(t)

	var authz, proof string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		authz = req.Header().Get("Authorization")
		proof = req.Header().Get("DPoP")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	auth := dpopAuth{state: st, proofer: proofer, nonce: "", serverURL: ""}
	wrapped := auth.WrapUnary(next)
	req := connect.NewRequest(&nokkuv1.User{})
	_, err := wrapped(context.Background(), req)
	require.NoError(t, err)
	assert.Empty(t, authz, "expected no Authorization header")
	assert.Empty(t, proof, "expected no DPoP proof header")
}

func TestDPoPAuthHTUUsesCanonicalServerURL(t *testing.T) {
	t.Parallel()
	st := &state.State{
		SessionToken: "sess-token", APIURL: "http://localhost:3000",
	}
	a := &dpopAuth{
		state:     st,
		proofer:   newTestProofer(t),
		serverURL: "https://app.example.com", // canonical URL advertised by the server
	}

	header := http.Header{}
	require.NoError(t, a.sign(header, "/nokku.v1.UserService/Whoami"))

	var claims struct {
		HTU string `json:"htu"`
	}
	parseProofClaims(t, header.Get("DPoP"), &claims)
	assert.Equal(t, "https://app.example.com/nokku.v1.UserService/Whoami", claims.HTU)
}

func TestDPoPAuthLearnsNonceAndServerURL(t *testing.T) {
	t.Parallel()
	st := &state.State{APIURL: "http://localhost:3000"}
	a := &dpopAuth{state: st, proofer: newTestProofer(t)}

	// Stale-nonce connect error (the RPC retry path).
	cerr := connect.NewError(connect.CodeUnauthenticated, errors.New("stale DPoP nonce"))
	cerr.Meta().Set("DPoP-Nonce", "nonce-2")
	cerr.Meta().Set(urlHeader, "https://app.example.com")
	require.True(t, a.learnNonce(cerr))

	// Raw device-flow response (the login path).
	h := http.Header{}
	h.Set("DPoP-Nonce", "nonce-3")
	a.learnResponse(h)

	a.mu.Lock()
	nonce, serverURL := a.nonce, a.serverURL
	a.mu.Unlock()
	assert.Equal(t, "nonce-3", nonce)
	assert.Equal(t, "https://app.example.com", serverURL)
	assert.Equal(t, "https://app.example.com", a.htuBase())
}

// parseProofClaims decodes an unsigned DPoP proof's payload into claims.
func parseProofClaims(t *testing.T, proof string, claims any) {
	t.Helper()
	parsed, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(parsed.UnsafePayloadWithoutVerification(), claims))
}
