package state

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/paths"
)

func setHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsurePaths())
}

// runFlags parses args with the root flags and returns the resulting state.
func runFlags(t *testing.T, args ...string) (*State, error) {
	t.Helper()
	var (
		s   *State
		err error
	)
	cmd := &cli.Command{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "api", Value: "https://app.nokku.sh"},
			&cli.StringFlag{Name: "token"},
			&cli.DurationFlag{Name: "ttl"},
			&cli.BoolFlag{Name: "require-tpm"},
			&cli.BoolFlag{Name: "insecure"},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			s, err = FromCommand(cmd)
			return nil
		},
	}
	require.NoError(t, cmd.Run(t.Context(), append([]string{"nk"}, args...)))
	return s, err
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

func TestFromCommandKeepsStoredAPI(t *testing.T) {
	setHome(t)
	require.NoError(t, (&State{
		APIURL: "https://self.example", SessionToken: "sess",
		Targets: []Target{{ID: "t"}},
	}).Save())

	s, err := runFlags(t)
	require.NoError(t, err)
	assert.Equal(t, "https://self.example", s.APIURL, "the default must not override a stored server")
	assert.Equal(t, "sess", s.SessionToken)
}

func TestFromCommandNewAPIDropsSession(t *testing.T) {
	setHome(t)
	require.NoError(t, (&State{
		APIURL: "https://a.example", SessionToken: "sess",
		Targets: []Target{{ID: "t"}},
	}).Save())

	s, err := runFlags(t, "--api", "https://b.example")
	require.NoError(t, err)
	assert.Equal(t, "https://b.example", s.APIURL)
	assert.Empty(t, s.SessionToken, "a session never goes to another server")
	assert.Empty(t, s.Targets)
}

func TestFromCommandRejectsNonServiceToken(t *testing.T) {
	setHome(t)
	_, err := runFlags(t, "--token", "sess-abc")
	require.ErrorContains(t, err, "nokku_sa_")

	s, err := runFlags(t, "--token", "nokku_sa_abc")
	require.NoError(t, err)
	assert.True(t, s.IsServiceAccount())
	assert.True(t, s.SessionValid())
}

func TestSessionValid(t *testing.T) {
	t.Parallel()
	assert.False(t, (&State{}).SessionValid())
	assert.True(t, (&State{SessionToken: "tok"}).SessionValid(), "unknown expiry counts as valid")
	assert.True(t, (&State{SessionToken: "tok", SessionExpiresAt: time.Now().Add(time.Hour)}).SessionValid())
	assert.False(t, (&State{SessionToken: "tok", SessionExpiresAt: time.Now().Add(-time.Minute)}).SessionValid())
}
