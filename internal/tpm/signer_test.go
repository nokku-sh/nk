package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func verifySignature(t *testing.T, pub crypto.PublicKey, data, sig []byte) {
	t.Helper()
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", pub)
	}
	digest := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(ecdsaPub, digest[:], sig) {
		t.Fatal("signature verification failed")
	}
}

func sign(t *testing.T, s crypto.Signer, data []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(data)
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
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
	pub1 := s1.Public()

	// The primary key is derived deterministically from the TPM seed, so a
	// fresh creation must produce the same public key (nothing persisted).
	s2, err := createTPMSigner(sim)
	if err != nil {
		t.Fatalf("recreate signer: %v", err)
	}
	defer s2.Close()
	if !pub1.(*ecdsa.PublicKey).Equal(s2.Public().(*ecdsa.PublicKey)) {
		t.Fatal("TPM public key is not deterministic across restarts")
	}

	data := []byte("hello nokku")
	verifySignature(t, pub1, data, sign(t, s1, data))
}

// TestTPMSignerAppIsolation verifies the CLI salt differs from the
// daemon's, so both derive distinct keys from the same TPM.
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

	cliPub := cli.Public()

	// The key is still deterministic for this app.
	cli2, err := createTPMSigner(sim)
	if err != nil {
		t.Fatalf("recreate cli signer: %v", err)
	}
	defer cli2.Close()
	if !cliPub.(*ecdsa.PublicKey).Equal(cli2.Public().(*ecdsa.PublicKey)) {
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
	pub1 := s1.Public()

	data := []byte("hello nokku")
	verifySignature(t, pub1, data, sign(t, s1, data))

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
	if !pub1.(*ecdsa.PublicKey).Equal(s2.Public().(*ecdsa.PublicKey)) {
		t.Fatal("public key changed after reload")
	}
	verifySignature(t, pub1, data, sign(t, s2, data))
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
	pub2 := s2.Public()

	st2, err := loadState(dir)
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if st2.PubKey != string(pemFor(pub2)) {
		t.Fatal("recovered key was not persisted")
	}

	verifySignature(t, pub2, []byte("hello nokku"), sign(t, s2, []byte("hello nokku")))
}

func pemFor(pub crypto.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
