package state

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nk/internal/paths"
)

func setHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsureDirs())
}

func TestSaveLoadRoundTrip(t *testing.T) {
	setHome(t)
	expires := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	s := &State{
		APIURL: "https://a.example", SessionToken: "sess", SessionExpiresAt: expires,
		Targets: []Target{{ID: "t", Name: "web"}}, User: &User{ID: "u"},
		Token: "nokku_sa_secret",
		TTL:   time.Hour,
	}
	require.NoError(t, s.Save())

	loaded := Load()
	assert.Equal(t, s.Config.APIURL, loaded.APIURL)
	assert.Equal(t, "sess", loaded.SessionToken)
	assert.True(t, loaded.SessionExpiresAt.Equal(expires))
	assert.Equal(t, s.Cache, loaded.Cache)
	assert.Zero(t, loaded.TTL, "flags are never persisted")

	raw, err := os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "nokku_sa_secret")
	fi, err := os.Stat(paths.ConfigFile())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestSessionValid(t *testing.T) {
	t.Parallel()
	assert.False(t, (&State{}).SessionValid())
	assert.True(t, (&State{SessionToken: "tok"}).SessionValid(), "unknown expiry counts as valid")
	assert.True(t, (&State{SessionToken: "tok", SessionExpiresAt: time.Now().Add(time.Hour)}).SessionValid())
	assert.False(t, (&State{SessionToken: "tok", SessionExpiresAt: time.Now().Add(-time.Minute)}).SessionValid())
}
