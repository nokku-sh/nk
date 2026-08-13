package ssh

import (
	"os"
	"strings"
	"testing"

	"github.com/nokku-sh/nk/internal/tpm"
	"github.com/nokku-sh/nk/internal/util"
)

// TestSetupTPMKey exercises the TPM identity lifecycle against a real
// TPM: login, determinism across runs, and switching between software
// and TPM identities. Manual test, run with:
//
//	NK_TPM_E2E=1 XDG_CONFIG_HOME=$(mktemp -d) go test -run TestSetupTPMKey ./internal/ssh/
func TestSetupTPMKey(t *testing.T) {
	if os.Getenv("NK_TPM_E2E") == "" {
		t.Skip("manual test: NK_TPM_E2E=1 XDG_CONFIG_HOME=$(mktemp -d)")
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg == "" ||
		!strings.HasPrefix(util.ConfigPath(), xdg) {
		t.Fatal("XDG_CONFIG_HOME must be set to a scratch dir before the test binary starts")
	}
	probe, err := tpm.OpenKey(sshTPMSalt)
	if err != nil {
		t.Skipf("no TPM available: %v", err)
	}
	_ = probe.Close()

	if err = os.MkdirAll(util.CertPath(), 0o700); err != nil {
		t.Fatal(err)
	}

	// Login: only the public key may touch disk.
	if err = SetupKey("tpm"); err != nil {
		t.Fatalf("SetupKey(tpm): %v", err)
	}
	if !TPMKeyActive() {
		t.Fatal("expected a TPM identity: public key without a private key file")
	}
	pub, err := os.ReadFile(util.PubKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pub), "ecdsa-sha2-nistp256 ") {
		t.Fatalf("unexpected TPM public key format: %q", pub)
	}

	// Deterministic primary: re-running reproduces the same key.
	if err = SetupKey("tpm"); err != nil {
		t.Fatalf("SetupKey(tpm) again: %v", err)
	}
	pub2, err := os.ReadFile(util.PubKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	if string(pub) != string(pub2) {
		t.Fatal("TPM public key changed across runs")
	}

	// Switching to a software key writes both key files again.
	if err = SetupKey("ecdsa-p256"); err != nil {
		t.Fatalf("SetupKey(ecdsa-p256): %v", err)
	}
	if TPMKeyActive() {
		t.Fatal("expected a software identity")
	}

	// Switching back to the TPM must remove the software private key and any
	// certificates issued for it (they are re-signed for the TPM key).
	fakeCert := util.Certificate("fake-ca")
	if err = os.WriteFile(fakeCert, []byte("fake-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = SetupKey("tpm"); err != nil {
		t.Fatalf("SetupKey(tpm) switchback: %v", err)
	}
	if !TPMKeyActive() {
		t.Fatal("expected a TPM identity after switching back")
	}
	if util.FileExists(fakeCert) {
		t.Fatal("stale certificate was not removed after the identity changed")
	}
	pub3, err := os.ReadFile(util.PubKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	if string(pub) != string(pub3) {
		t.Fatal("TPM public key changed after switching back")
	}
}
