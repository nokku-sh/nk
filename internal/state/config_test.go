package state

import (
	"os"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nk/internal/paths"
)

// setTestConfigDir redirects the app's config dir into a fresh temp dir so
// tests never touch the real config. xdg paths resolve at init, so the
// exported var is swapped instead (nolint:reassign // test isolation).
func setTestConfigDir(t *testing.T) {
	t.Helper()
	old := xdg.ConfigHome
	xdg.ConfigHome = t.TempDir()               //nolint:reassign // test isolation
	t.Cleanup(func() { xdg.ConfigHome = old }) //nolint:reassign // test isolation
}

func TestConfigSaveLoadRoundTrip(t *testing.T) {
	setTestConfigDir(t)
	require.NoError(t, os.MkdirAll(paths.ConfigPath(), 0o700))

	expires := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)

	s := &State{
		APIURL:           "https://app.example.com",
		TTL:              4 * time.Hour,
		SessionToken:     "sess-token",
		SessionExpiresAt: expires,
	}
	require.NoError(t, s.Save())

	loaded := New()
	assert.Equal(t, "https://app.example.com", loaded.APIURL)
	assert.Equal(t, 4*time.Hour, loaded.TTL)
	assert.Equal(t, "sess-token", loaded.SessionToken)
	assert.True(t, loaded.SessionExpiresAt.Equal(expires))
}

func TestConfigLoadMissingFileIsNoOp(t *testing.T) {
	setTestConfigDir(t)

	c := &Config{APIURL: "https://fallback.example.com"}
	require.NoError(t, c.Load())
	assert.Equal(t, "https://fallback.example.com", c.APIURL,
		"Load on a missing file must leave the config untouched")
}

func TestConfigLoadCorrupt(t *testing.T) {
	setTestConfigDir(t)
	require.NoError(t, os.MkdirAll(paths.ConfigPath(), 0o700))
	require.NoError(t, os.WriteFile(paths.ConfigFile(), []byte("{not json"), 0o600))

	var c Config
	err := c.Load()
	assert.ErrorContains(t, err, "parsing config")
}

func TestConfigSavePerms(t *testing.T) {
	setTestConfigDir(t)

	require.NoError(t, os.MkdirAll(paths.ConfigPath(), 0o700))
	s := &State{APIURL: "https://app.example.com"}
	require.NoError(t, s.Save())

	fi, err := os.Stat(paths.ConfigFile())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(),
		"the config carries the session token and must be 0600")
}

func TestStateSaveNeverPersistsServiceAccountToken(t *testing.T) {
	setTestConfigDir(t)

	require.NoError(t, os.MkdirAll(paths.ConfigPath(), 0o700))
	s := &State{
		Token:        "nokku_sa_secret",
		APIURL:       "https://app.example.com",
		SessionToken: "sess-token",
		Targets:      []Target{{ID: "t-1", Name: "prod"}},
	}
	require.NoError(t, s.Save())

	raw, err := os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "nokku_sa_secret",
		"the service account token is ephemeral and must never be written to disk")
	assert.Contains(t, string(raw), "sess-token",
		"the DPoP-bound session token is persisted on purpose")
}

func TestStateSaveCorruptCacheFails(t *testing.T) {
	setTestConfigDir(t)
	require.NoError(t, os.MkdirAll(paths.ConfigPath(), 0o700))

	// A directory where the cache file belongs makes the cache save fail
	// while the config save succeeds.
	require.NoError(t, os.Mkdir(paths.CacheFile(), 0o700))

	s := &State{APIURL: "https://app.example.com"}
	err := s.Save()
	assert.ErrorContains(t, err, "saving cache")
}

func TestCacheSaveLoadRoundTrip(t *testing.T) {
	setTestConfigDir(t)

	require.NoError(t, os.MkdirAll(paths.ConfigPath(), 0o700))
	c := &Cache{
		User:           &User{ID: "user-1", Name: "alice"},
		Workspaces:     []Workspace{{ID: "ws-1", Name: "production"}},
		Targets:        []Target{{ID: "t-1", Name: "prod", CAID: "ca-1"}},
		CAs:            []CA{{ID: "ca-1", Name: "Production CA", PublicKey: "key1"}},
		ServiceAccount: &ServiceAccount{ID: "sa-1", Name: "bot"},
	}
	require.NoError(t, c.Save())

	var loaded Cache
	require.NoError(t, loaded.Load())
	assert.Equal(t, c, &loaded)
}

func TestCacheLoadCorrupt(t *testing.T) {
	setTestConfigDir(t)
	require.NoError(t, os.MkdirAll(paths.ConfigPath(), 0o700))
	require.NoError(t, os.WriteFile(paths.CacheFile(), []byte("]]]"), 0o600))

	var c Cache
	err := c.Load()
	assert.ErrorContains(t, err, "parsing cache")
}

func TestNewLoadsWithoutConfigDir(t *testing.T) {
	setTestConfigDir(t)

	s := New()
	assert.NotNil(t, s)
	assert.Empty(t, s.APIURL)
	assert.Nil(t, s.User)
}
