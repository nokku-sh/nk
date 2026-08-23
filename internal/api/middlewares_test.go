package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"
	"github.com/mizuchilabs/kagi/dpop"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/state"
)

func newTestProofer(t *testing.T) *dpop.Proofer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p, err := dpop.NewProofer(key, dpop.ProoferOptions{})
	if err != nil {
		t.Fatalf("new proofer: %v", err)
	}
	return p
}

func TestDPoPAuthInteractiveSignsRequest(t *testing.T) {
	t.Parallel()
	st := &state.State{
		Config: state.Config{SessionToken: "sess-token", APIURL: "https://app.example.com"},
	}
	proofer := newTestProofer(t)

	var authz, proof string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		authz = req.Header().Get("Authorization")
		proof = req.Header().Get("DPoP")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	wrapped := WithDPoP(st, proofer, "").WrapUnary(next)
	req := connect.NewRequest(&nokkuv1.User{})
	if _, err := wrapped(context.Background(), req); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if authz != "DPoP sess-token" {
		t.Errorf("Authorization = %q, want DPoP sess-token", authz)
	}
	if proof == "" {
		t.Error("expected a DPoP proof header")
	}
}

func TestDPoPAuthHTUHasNoDoubleSlash(t *testing.T) {
	t.Parallel()
	st := &state.State{
		Config: state.Config{SessionToken: "sess-token", APIURL: "https://app.example.com"},
	}
	proofer := newTestProofer(t)

	a := &dpopAuth{state: st, proofer: proofer}
	header := http.Header{}
	a.sign(header, "/nokku.v1.UserService/Whoami")

	proof := header.Get("DPoP")
	if proof == "" {
		t.Fatal("expected a DPoP proof header")
	}

	parsed, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	var claims struct {
		HTU string `json:"htu"`
	}
	if err = json.Unmarshal(parsed.UnsafePayloadWithoutVerification(), &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.HTU != "https://app.example.com/nokku.v1.UserService/Whoami" {
		t.Fatalf("proof htu = %q", claims.HTU)
	}
}

func TestDPoPAuthSkipsServiceAccount(t *testing.T) {
	t.Parallel()
	st := &state.State{
		Token:  "key-123.secret",
		Config: state.Config{APIURL: "https://app.example.com"},
	}
	proofer := newTestProofer(t)

	var proof string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		proof = req.Header().Get("DPoP")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	wrapped := WithDPoP(st, proofer, "").WrapUnary(next)
	req := connect.NewRequest(&nokkuv1.User{})
	if _, err := wrapped(context.Background(), req); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if proof != "" {
		t.Errorf("DPoP = %q, want empty for service accounts", proof)
	}
}

func TestDPoPAuthNoSessionNoHeaders(t *testing.T) {
	t.Parallel()
	st := &state.State{Config: state.Config{APIURL: "https://app.example.com"}}
	proofer := newTestProofer(t)

	var authz, proof string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		authz = req.Header().Get("Authorization")
		proof = req.Header().Get("DPoP")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	wrapped := WithDPoP(st, proofer, "").WrapUnary(next)
	req := connect.NewRequest(&nokkuv1.User{})
	if _, err := wrapped(context.Background(), req); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if authz != "" || proof != "" {
		t.Errorf("expected no auth headers, got Authorization=%q DPoP=%q", authz, proof)
	}
}

var _ = http.MethodPost
