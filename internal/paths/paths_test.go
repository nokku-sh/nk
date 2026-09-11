package paths

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestEnsureSSHConfigInclude(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	sshDir := filepath.Join(home, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0o700))
	configPath := filepath.Join(sshDir, "config")
	include := "Include " + SSHConfigFile()

	t.Run("creates the config when missing", func(t *testing.T) {
		require.NoError(t, EnsureSSHConfigInclude())
		content, rerr := os.ReadFile(configPath)
		require.NoError(t, rerr)
		assert.Contains(t, string(content), include)
	})

	t.Run("prepends include preserving existing content", func(t *testing.T) {
		existing := "Host own\n    HostName example.com\n"
		require.NoError(t, os.WriteFile(configPath, []byte(existing), 0o600))

		require.NoError(t, EnsureSSHConfigInclude())
		content, rerr := os.ReadFile(configPath)
		require.NoError(t, rerr)
		assert.Contains(t, string(content), include)
		assert.Contains(t, string(content), existing,
			"the user's own ssh config must be preserved")
	})

	t.Run("does not duplicate the include", func(t *testing.T) {
		before, rerr := os.ReadFile(configPath)
		require.NoError(t, rerr)

		require.NoError(t, EnsureSSHConfigInclude())
		after, aerr := os.ReadFile(configPath)
		require.NoError(t, aerr)
		assert.Equal(t, string(before), string(after),
			"an existing include must be left untouched")
	})
}

func TestRemoveSSHConfigInclude(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	sshDir := filepath.Join(home, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0o700))
	configPath := filepath.Join(sshDir, "config")

	t.Run("missing config is a no-op", func(t *testing.T) {
		require.NoError(t, RemoveSSHConfigInclude())
	})

	t.Run("round trips to the original content", func(t *testing.T) {
		original := "Host own\n    HostName example.com\n"
		require.NoError(t, os.WriteFile(configPath, []byte(original), 0o600))

		require.NoError(t, EnsureSSHConfigInclude())
		require.NoError(t, RemoveSSHConfigInclude())

		content, rerr := os.ReadFile(configPath)
		require.NoError(t, rerr)
		assert.Equal(t, original, string(content))
	})

	t.Run("leaves a config without the include untouched", func(t *testing.T) {
		require.NoError(t, os.WriteFile(configPath, []byte("Host own\n"), 0o600))
		require.NoError(t, RemoveSSHConfigInclude())

		content, rerr := os.ReadFile(configPath)
		require.NoError(t, rerr)
		assert.Equal(t, "Host own\n", string(content))
	})
}

func TestCertificateFilenames(t *testing.T) {
	path, err := SSHCertificate("ca-test")
	require.NoError(t, err)
	assert.Equal(t, "ca-test-cert.pub", filepath.Base(path))

	path, err = SSHCertificate("ca-123")
	require.NoError(t, err)
	assert.Equal(t, "ca-123-cert.pub", filepath.Base(path))
}

// TestSSHCertificateRejectsUnsafeIDs covers a backend supplied id reaching the
// filesystem: anything that is not a plain path segment would escape the certs
// directory.
func TestSSHCertificateRejectsUnsafeIDs(t *testing.T) {
	for _, id := range []string{
		"",
		".",
		"..",
		"../../../../tmp/pwned",
		"nested/id",
		`nested\id`,
		"ca id",
		"ca\nid",
		"ca\x00id",
	} {
		path, err := SSHCertificate(id)
		require.Error(t, err, "SSHCertificate(%q) must be refused", id)
		assert.Empty(t, path)
	}
}

// TestPathDerivationWithoutHome pins the no-home behaviour: startup stops and
// state is never steered into the shared temp dir.
func TestPathDerivationWithoutHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("UserConfigDir does not derive from HOME on windows")
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")

	assert.Equal(t, ConfigDirname, ConfigPath(),
		"state must degrade instead of falling back to a shared temp dir")
	assert.Error(t, EnsurePaths(), "startup must stop when no config dir resolves")
}

func TestKnownHostsPathConsistency(t *testing.T) {
	p1 := KnownHostsPath()
	p2 := KnownHostsPath()
	assert.Equal(t, p1, p2)
}
