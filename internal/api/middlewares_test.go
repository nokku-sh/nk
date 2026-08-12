package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/tpm"
)

// fakeSigner is a software tpm.Signer for tests.
type fakeSigner struct {
	key *ecdsa.PrivateKey
}

func (f *fakeSigner) Method() string { return tpm.MethodSoft }

func (f *fakeSigner) Public() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func (f *fakeSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, f.key, digest[:])
}

func (f *fakeSigner) Close() error { return nil }

func newFakeSigner(t *testing.T) *fakeSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &fakeSigner{key: key}
}

// TestChallengeFormat pins the signed challenge wire format:
//
//	<deviceID>:<unixSeconds>:<nonceHex>:<procedure>:<base64url(signature)>
//
// with the signature covering everything before the final colon.
func TestChallengeFormat(t *testing.T) {
	t.Parallel()
	fs := newFakeSigner(t)
	a := &auth{signer: fs}

	ch, err := a.challenge(context.Background(), "dev-123", "nokku.v1.AuthService/Login")
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	parts := strings.Split(ch, ":")
	if len(parts) != 5 {
		t.Fatalf("challenge = %q, want 5 colon-separated parts, got %d", ch, len(parts))
	}
	if parts[0] != "dev-123" {
		t.Errorf("device id = %q, want dev-123", parts[0])
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		t.Fatalf("timestamp %q is not an integer: %v", parts[1], err)
	}
	if delta := time.Since(time.Unix(ts, 0)); delta > 5*time.Second || delta < -5*time.Second {
		t.Errorf("challenge timestamp is stale: %v ago", delta)
	}
	nonce, err := hex.DecodeString(parts[2])
	if err != nil || len(nonce) != 12 {
		t.Errorf(
			"nonce %q must be 12 raw bytes of hex, got len %d (err=%v)",
			parts[2],
			len(nonce),
			err,
		)
	}
	if parts[3] != "nokku.v1.AuthService/Login" {
		t.Errorf("procedure = %q, want nokku.v1.AuthService/Login", parts[3])
	}

	// The signature must cover deviceID:ts:nonce:procedure and verify with
	// the signer's public key.
	sig, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("signature is not base64url: %v", err)
	}
	payload := strings.Join(parts[:4], ":")
	digest := sha256.Sum256([]byte(payload))
	if !ecdsa.VerifyASN1(&fs.key.PublicKey, digest[:], sig) {
		t.Fatal("challenge signature does not verify over the payload")
	}
}

func TestWithAuthServiceAccount(t *testing.T) {
	t.Parallel()
	st := &state.State{Token: "nks_abc123"}

	var got string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		got = req.Header().Get("Authorization")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	wrapped := WithAuth(st, nil).WrapUnary(next)
	req := connect.NewRequest(&nokkuv1.User{})
	if _, err := wrapped(context.Background(), req); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if got != "Bearer nks_abc123" {
		t.Errorf("Authorization = %q, want Bearer nks_abc123", got)
	}
}

func TestWithAuthDeviceChallenge(t *testing.T) {
	t.Parallel()
	st := &state.State{Config: state.Config{DeviceID: "dev-1"}}
	fs := newFakeSigner(t)

	var authz, deviceID string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		authz = req.Header().Get("Authorization")
		deviceID = req.Header().Get("Nokku-Client-Device-Id")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	wrapped := WithAuth(st, fs).WrapUnary(next)
	req := connect.NewRequest(&nokkuv1.User{})
	if _, err := wrapped(context.Background(), req); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if !strings.HasPrefix(authz, "Nokku ") {
		t.Errorf("Authorization = %q, want Nokku-prefixed challenge", authz)
	}
	if deviceID != "dev-1" {
		t.Errorf("Nokku-Client-Device-Id = %q, want dev-1", deviceID)
	}
}

func TestWithAuthNoCredentials(t *testing.T) {
	t.Parallel()
	st := &state.State{}

	var authz string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		authz = req.Header().Get("Authorization")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	wrapped := WithAuth(st, nil).WrapUnary(next)
	req := connect.NewRequest(&nokkuv1.User{})
	if _, err := wrapped(context.Background(), req); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if authz != "" {
		t.Errorf("Authorization = %q, want empty with no credentials", authz)
	}
}
