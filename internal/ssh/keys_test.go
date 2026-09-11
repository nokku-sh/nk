package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/nokku-sh/mon/fsutil"

	"github.com/nokku-sh/nk/internal/paths"
)

// setTestConfigDir redirects the app's config dir into a fresh temp dir
// so tests never touch the real config.
func setTestConfigDir(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

func setupSSHDir(t *testing.T) {
	t.Helper()
	setTestConfigDir(t)
	for _, sub := range []string{"", "certs"} {
		require.NoError(t, os.MkdirAll(filepath.Join(paths.ConfigPath(), sub), 0o700))
	}
}

// TestSetupKey exercises the entry point: it must produce a public key
// regardless of whether a TPM is present (the software key is the fallback).
func TestSetupKey(t *testing.T) {
	setupSSHDir(t)

	require.NoError(t, SetupKey(false))
	assert.True(t, fsutil.FileExists(paths.PubKeyFile()), "public key not created")
}

// TestSetupKeyReplacesLegacyIdentity covers the upgrade path: the pre-Signer
// key files and the artifacts derived from them go away, and the identity is
// stable on the next run.
func TestSetupKeyReplacesLegacyIdentity(t *testing.T) {
	setupSSHDir(t)

	// A pre-Signer plaintext key and a pre-Signer sealed key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := cryptossh.MarshalPrivateKey(priv, "legacy@nokku")
	require.NoError(t, err)
	require.NoError(t, fsutil.WriteFile(paths.KeyFile(), pem.EncodeToMemory(block), 0o600))
	require.NoError(t, fsutil.WriteFile(paths.SoftKeyFile(), []byte(`{"salt":"x"}`), 0o600))

	// A stale public key and a certificate issued for the legacy identity.
	certPath, err := paths.SSHCertificate("ca-1")
	require.NoError(t, err)
	require.NoError(t, fsutil.WriteFile(
		paths.PubKeyFile(), []byte("ssh-ed25519 AAAAstale legacy@nokku\n"), 0o600,
	))
	require.NoError(t, fsutil.WriteFile(
		certPath, []byte("ssh-ed25519-cert-v01@openssh.com AAAAstale\n"), 0o600,
	))

	require.NoError(t, SetupKey(false))

	assert.False(t, fsutil.FileExists(paths.KeyFile()), "the plaintext key must be removed")
	assert.False(t, fsutil.FileExists(paths.SoftKeyFile()), "the sealed key must be removed")
	assert.False(t, fsutil.FileExists(certPath),
		"certificates for the old identity must be removed")

	pub, err := os.ReadFile(paths.PubKeyFile())
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(pub), "ecdsa-sha2-nistp256 "),
		"the identity must be replaced with a signer key: %q", pub)

	// The signer derives the same key on the next run, so a certificate
	// issued now stays usable.
	require.NoError(t, SetupKey(false))
	pub2, err := os.ReadFile(paths.PubKeyFile())
	require.NoError(t, err)
	assert.Equal(t, pub, pub2, "the identity must be stable across runs")
}

func TestGetPubKey(t *testing.T) {
	setupSSHDir(t)

	require.NoError(t, SetupKey(false))

	key, err := GetPubKey()
	require.NoError(t, err)
	assert.NotEmpty(t, key)
}
