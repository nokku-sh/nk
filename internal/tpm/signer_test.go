package tpm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func verifySignature(t *testing.T, pubPEM, data, sig []byte) {
	t.Helper()
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		t.Fatal("public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", pub)
	}
	digest := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(ecdsaPub, digest[:], sig) {
		t.Fatal("signature verification failed")
	}
}

func TestTPMSigner(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("tpm simulator unavailable: %v", err)
	}
	defer sim.Close()

	s1, err := createTPMSigner(sim)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	defer s1.Close()
	pub1, err := s1.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}

	// The primary key is derived deterministically from the TPM seed, so a
	// fresh creation must produce the same public key (nothing persisted).
	s2, err := createTPMSigner(sim)
	if err != nil {
		t.Fatalf("recreate signer: %v", err)
	}
	defer s2.Close()
	pub2, err := s2.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	if !bytes.Equal(pub1, pub2) {
		t.Fatal("TPM public key is not deterministic across restarts")
	}

	data := []byte("hello nokku")
	sig, err := s1.Sign(context.Background(), data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verifySignature(t, pub1, data, sig)

	if s1.Method() != MethodTPM {
		t.Fatalf("Method() = %q, want %q", s1.Method(), MethodTPM)
	}
}

// TestTPMSignerAppIsolation verifies that the CLI key is namespaced away
// from the daemon's: the daemon and the CLI share a TPM on a machine, and a
// shared template would give them the same identity. The salt is part of the
// derivation, so the CLI salt ("nokku-cli") must never match the daemon's
// ("nokku-daemon").
func TestTPMSignerAppIsolation(t *testing.T) {
	if string(signerSalt) == "nokku-daemon" {
		t.Fatal("CLI signer must not share the daemon's salt; see the signerSalt comment")
	}

	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("tpm simulator unavailable: %v", err)
	}
	defer sim.Close()

	cli, err := createTPMSigner(sim)
	if err != nil {
		t.Fatalf("create cli signer: %v", err)
	}
	defer cli.Close()

	cliPub, _ := cli.Public()

	// The key is still deterministic for this app.
	cli2, err := createTPMSigner(sim)
	if err != nil {
		t.Fatalf("recreate cli signer: %v", err)
	}
	defer cli2.Close()
	cliPub2, _ := cli2.Public()
	if !bytes.Equal(cliPub, cliPub2) {
		t.Fatal("CLI public key is not deterministic across restarts")
	}
}

func TestSignerSalt(t *testing.T) {
	if string(signerSalt) != "nokku-cli" {
		t.Fatalf(
			"signerSalt = %q, want %q (must not match the daemon's salt)",
			signerSalt,
			"nokku-cli",
		)
	}
}

func TestSoftSignerRoundTrip(t *testing.T) {
	dir := t.TempDir()

	s1, err := openSoft(dir, nil)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	defer s1.Close()
	pub1, err := s1.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}

	data := []byte("hello nokku")
	sig, err := s1.Sign(context.Background(), data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verifySignature(t, pub1, data, sig)

	if s1.Method() != MethodSoft {
		t.Fatalf("Method() = %q, want %q", s1.Method(), MethodSoft)
	}

	// Reloading from disk must yield the same key.
	st, err := loadState(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st == nil {
		t.Fatal("no state written")
	}
	s2, err := openSoft(dir, st)
	if err != nil {
		t.Fatalf("reload signer: %v", err)
	}
	defer s2.Close()
	pub2, err := s2.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	if !bytes.Equal(pub1, pub2) {
		t.Fatal("public key changed after reload")
	}
	sig2, err := s2.Sign(context.Background(), data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verifySignature(t, pub1, data, sig2)
}

func TestSoftSignerRecoversOnMachineChange(t *testing.T) {
	dir := t.TempDir()

	s, err := openSoft(dir, nil)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	_ = s.Close()

	st, err := loadState(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if _, err = rand.Read(st.Salt); err != nil {
		t.Fatalf("corrupt salt: %v", err)
	}

	// A changed machine identity (corrupted salt) must not hard-fail: a new
	// key is created and persisted instead.
	s2, err := openSoft(dir, st)
	if err != nil {
		t.Fatalf("openSoft should recover by creating a new key, got: %v", err)
	}
	defer s2.Close()
	pub2, err := s2.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}

	st2, err := loadState(dir)
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if st2.PubKey != string(pub2) {
		t.Fatal("recovered key was not persisted")
	}

	sig, err := s2.Sign(context.Background(), []byte("hello nokku"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verifySignature(t, pub2, []byte("hello nokku"), sig)
}
