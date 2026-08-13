package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestKeySign(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("tpm simulator unavailable: %v", err)
	}
	defer func() { _ = sim.Close() }()

	k, err := NewKey(sim, []byte("test-key"))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	defer func() { _ = k.Close() }()

	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() is %T, want *ecdsa.PublicKey", k.Public())
	}

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature verification failed")
	}

	// The key template pins SHA-256: other hashes must be rejected.
	if _, err = k.Sign(rand.Reader, digest[:], crypto.SHA512); err == nil {
		t.Fatal("expected error for non-SHA-256 hash")
	}
}

func TestKeyDeterministicAndSalted(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("tpm simulator unavailable: %v", err)
	}
	defer func() { _ = sim.Close() }()

	// The same salt must reproduce the key, nothing persisted.
	pubFor := func(salt []byte) *ecdsa.PublicKey {
		t.Helper()
		k, kerr := NewKey(sim, salt)
		if kerr != nil {
			t.Fatalf("NewKey: %v", kerr)
		}
		defer func() { _ = k.Close() }()
		pub, ok := k.Public().(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("Public() is %T, want *ecdsa.PublicKey", k.Public())
		}
		return pub
	}

	a := pubFor([]byte("test-key"))
	b := pubFor([]byte("test-key"))
	if !a.Equal(b) {
		t.Fatal("key is not deterministic for the same salt")
	}

	c := pubFor([]byte("other-salt"))
	if a.Equal(c) {
		t.Fatal("different salts must derive different keys")
	}

	// The SSH salt must not collide with the request-signing key.
	s, err := createTPMSigner(sim)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	defer func() { _ = s.Close() }()
	if a.Equal(s.key.pub) {
		t.Fatal("test salt must not derive the request-signing key")
	}
}
