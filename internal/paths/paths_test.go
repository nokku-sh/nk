package paths

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathDerivation(t *testing.T) {
	configDir := ConfigPath()
	assert.True(t, filepath.IsAbs(configDir), "ConfigPath() = %q, expected absolute path", configDir)
	assert.Equal(t, ConfigDirname, filepath.Base(configDir))

	for name, fn := range map[string]func() string{
		"ConfigFile":    ConfigFile,
		"CacheFile":     CacheFile,
		"KeyFile":       KeyFile,
		"PubKeyFile":    PubKeyFile,
		"SSHConfigFile": SSHConfigFile,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, configDir, filepath.Dir(fn()))
		})
	}

	t.Run("SSHCertPath", func(t *testing.T) {
		assert.Equal(t, configDir, filepath.Dir(SSHCertPath()))
	})
	t.Run("KnownHostsPath", func(t *testing.T) {
		assert.Equal(t, configDir, filepath.Dir(KnownHostsPath()))
	})
}

func TestSSHPath(t *testing.T) {
	path, err := SSHPath()
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(path), "SSHPath() = %q, expected absolute", path)
	assert.Equal(t, ".ssh", filepath.Base(path))

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".ssh"), path)
}

func TestCertificateFilenames(t *testing.T) {
	assert.Equal(t, "ca-test-cert.pub", filepath.Base(SSHCertificate("ca-test")))
	assert.Equal(t, "ca-123-cert.pub", filepath.Base(SSHCertificate("ca-123")))
}

func TestKnownHostsPathConsistency(t *testing.T) {
	p1 := KnownHostsPath()
	p2 := KnownHostsPath()
	assert.Equal(t, p1, p2)
}
