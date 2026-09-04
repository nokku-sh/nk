package ssh

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/mon/tpm"

	"github.com/nokku-sh/nk/internal/paths"
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
	xdg := os.Getenv("XDG_CONFIG_HOME")
	require.True(t, xdg != "" && strings.HasPrefix(paths.ConfigPath(), xdg),
		"XDG_CONFIG_HOME must be set to a scratch dir before the test binary starts")
	probe, err := tpm.OpenKey(sshTPMSalt)
	if err != nil {
		t.Skipf("no TPM available: %v", err)
	}
	_ = probe.Close()

	require.NoError(t, os.MkdirAll(paths.SSHCertPath(), 0o700))

	// Login: only the public key may touch disk.
	require.NoError(t, SetupKey(true), "SetupKey(true)")
	assert.True(t, TPMKeyActive(),
		"expected a TPM identity: public key without a private key file")
	pub, err := os.ReadFile(paths.PubKeyFile())
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(pub), "ecdsa-sha2-nistp256 "),
		"unexpected TPM public key format: %q", pub)

	// Deterministic primary: re-running reproduces the same key.
	require.NoError(t, SetupKey(true), "SetupKey(true) again")
	pub2, err := os.ReadFile(paths.PubKeyFile())
	require.NoError(t, err)
	assert.Equal(t, string(pub), string(pub2), "TPM public key changed across runs")
}
