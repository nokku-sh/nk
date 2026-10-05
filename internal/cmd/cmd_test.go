package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

func setHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsureDirs())
}

// runFlags parses args with the root flags and returns the resulting state.
func runFlags(t *testing.T, args ...string) (*state.State, error) {
	t.Helper()
	var (
		s   *state.State
		err error
	)
	cmd := &cli.Command{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "api", Value: "https://app.nokku.sh"},
			&cli.DurationFlag{Name: "ttl"},
			&cli.BoolFlag{Name: "require-tpm"},
			&cli.BoolFlag{Name: "insecure"},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			s, err = loadState(cmd)
			return nil
		},
	}
	require.NoError(t, cmd.Run(t.Context(), append([]string{"nk"}, args...)))
	return s, err
}

func TestLoadStateKeepsStoredAPI(t *testing.T) {
	setHome(t)
	require.NoError(t, (&state.State{
		APIURL: "https://self.example", SessionToken: "sess",
		Targets: []state.Target{{ID: "t"}},
	}).Save())

	s, err := runFlags(t)
	require.NoError(t, err)
	assert.Equal(t, "https://self.example", s.APIURL, "the default must not override a stored server")
	assert.Equal(t, "sess", s.SessionToken)
}

func TestLoadStateNewAPIDropsSession(t *testing.T) {
	setHome(t)
	require.NoError(t, (&state.State{
		APIURL: "https://a.example", SessionToken: "sess",
		Targets: []state.Target{{ID: "t"}},
	}).Save())

	s, err := runFlags(t, "--api", "https://b.example")
	require.NoError(t, err)
	assert.Equal(t, "https://b.example", s.APIURL)
	assert.Empty(t, s.SessionToken, "a session never goes to another server")
	assert.Empty(t, s.Targets)
}

func TestLoadStateRejectsNonServiceToken(t *testing.T) {
	setHome(t)
	t.Setenv("NK_TOKEN", "sess-abc")
	_, err := runFlags(t)
	require.ErrorContains(t, err, "nokku_sa_")

	t.Setenv("NK_TOKEN", "nokku_sa_abc")
	s, err := runFlags(t)
	require.NoError(t, err)
	assert.True(t, s.IsServiceAccount())
	assert.True(t, s.SessionValid())
}
