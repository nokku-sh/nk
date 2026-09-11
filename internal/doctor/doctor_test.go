package doctor

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		name   string
		checks []Check
		want   int
	}{
		{"all ok", []Check{{Status: StatusOK}, {Status: StatusInfo}}, 0},
		{"warning", []Check{{Status: StatusOK}, {Status: StatusWarn}}, 1},
		{"failure dominates warning", []Check{{Status: StatusWarn}, {Status: StatusFail}}, 2},
		{"empty", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Report{Checks: tt.checks}
			assert.Equal(t, tt.want, r.ExitCode())
		})
	}
}

func TestCertID(t *testing.T) {
	assert.Equal(t, "abc123", certID("/tmp/nk/certs/abc123-cert.pub"))
}

// TestCleanStaleCertsWithoutCache covers the destructive case: a missing or
// discarded cache.json leaves no CAs, and a repair run must not treat that as
// "every certificate is stale".
func TestCleanStaleCertsWithoutCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	require.NoError(t, os.MkdirAll(paths.SSHCertPath(), 0o700))

	certPath, err := paths.SSHCertificate("ca-1")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certPath, []byte("cert"), 0o600))

	assert.Empty(t, cleanStaleCerts(&state.State{}, nil))
	assert.FileExists(t, certPath,
		"a certificate must survive a repair run with no cached state")

	// With synced state that no longer lists the CA, the certificate is stale.
	fixed := cleanStaleCerts(&state.State{
		User:    &state.User{ID: "u-1"},
		Targets: []state.Target{{ID: "t-1", Name: "prod", CAID: "ca-2"}},
	}, nil)
	assert.NoFileExists(t, certPath)
	assert.NotEmpty(t, fixed)
}
