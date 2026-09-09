package ssh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nk/internal/fsutil"
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

func TestSetupFileKey(t *testing.T) {
	setupSSHDir(t)

	// First call creates the keypair.
	require.NoError(t, setupFileKey())
	assert.True(t, fsutil.FileExists(paths.KeyFile()), "private key not created")
	assert.True(t, fsutil.FileExists(paths.PubKeyFile()), "public key not created")

	// Second call is a no-op.
	require.NoError(t, setupFileKey())
}

func TestGetPubKey(t *testing.T) {
	setupSSHDir(t)

	require.NoError(t, setupFileKey())

	key, err := GetPubKey()
	require.NoError(t, err)
	assert.NotEmpty(t, key)
}
