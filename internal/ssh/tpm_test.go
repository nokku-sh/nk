package ssh

import (
	"os"
	"strings"
	"testing"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/tpm"
)

// TestSetupTPMKey exercises the TPM identity lifecycle against a real TPM:
// only the public key touches disk, and the key is deterministic across
// runs. Manual test, run with:
//
//	NK_TPM_E2E=1 XDG_CONFIG_HOME=$(mktemp -d) go test -run TestSetupTPMKey ./internal/ssh/
func TestSetupTPMKey(t *testing.T) {
	if os.Getenv("NK_TPM_E2E") == "" {
		t.Skip("manual test: NK_TPM_E2E=1 XDG_CONFIG_HOME=$(mktemp -d)")
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg == "" ||
		!strings.HasPrefix(paths.ConfigPath(), xdg) {
		t.Fatal("XDG_CONFIG_HOME must be set to a scratch dir before the test binary starts")
	}
	probe, err := tpm.OpenKey(sshTPMSalt)
	if err != nil {
		t.Skipf("no TPM available: %v", err)
	}
	_ = probe.Close()

	if err = os.MkdirAll(paths.SSHCertPath(), 0o700); err != nil {
		t.Fatal(err)
	}

	// Login: only the public key may touch disk.
	if err = SetupKey(true); err != nil {
		t.Fatalf("SetupKey(true): %v", err)
	}
	if !TPMKeyActive() {
		t.Fatal("expected a TPM identity: public key without a private key file")
	}
	pub, err := os.ReadFile(paths.PubKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pub), "ecdsa-sha2-nistp256 ") {
		t.Fatalf("unexpected TPM public key format: %q", pub)
	}

	// Deterministic primary: re-running reproduces the same key.
	if err = SetupKey(true); err != nil {
		t.Fatalf("SetupKey(true) again: %v", err)
	}
	pub2, err := os.ReadFile(paths.PubKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	if string(pub) != string(pub2) {
		t.Fatal("TPM public key changed across runs")
	}
}
