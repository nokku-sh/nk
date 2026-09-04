package ssh

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nk/internal/state"
)

func TestResolveTarget(t *testing.T) {
	t.Parallel()

	makeState := func(targets []state.Target, workspaces []state.Workspace) *state.State {
		return &state.State{Targets: targets, Workspaces: workspaces}
	}
	dupTargets := []state.Target{
		{ID: "1", Name: "db", WorkspaceID: "ws-1"},
		{ID: "2", Name: "db", WorkspaceID: "ws-2"},
	}
	dupWorkspaces := []state.Workspace{
		{ID: "ws-1", Name: "staging"},
		{ID: "ws-2", Name: "production"},
	}

	t.Run("finds a unique target by name", func(t *testing.T) {
		t.Parallel()
		s := makeState([]state.Target{{ID: "1", Name: "prod"}}, nil)
		got, err := ResolveTarget(s, "prod")
		require.NoError(t, err)
		assert.Equal(t, "1", got.ID)
	})

	t.Run("disambiguates by workspace name", func(t *testing.T) {
		t.Parallel()
		s := makeState(dupTargets, dupWorkspaces)
		got, err := ResolveTarget(s, "staging/db")
		require.NoError(t, err)
		assert.Equal(t, "1", got.ID)
	})

	t.Run("disambiguates by workspace id", func(t *testing.T) {
		t.Parallel()
		s := makeState(dupTargets, dupWorkspaces)
		got, err := ResolveTarget(s, "ws-2/db")
		require.NoError(t, err)
		assert.Equal(t, "2", got.ID)
	})

	t.Run("rejects an ambiguous bare name", func(t *testing.T) {
		t.Parallel()
		s := makeState(dupTargets, dupWorkspaces)
		_, err := ResolveTarget(s, "db")
		assert.Error(t, err, "expected ambiguity error")
	})

	t.Run("reports not found", func(t *testing.T) {
		t.Parallel()
		s := makeState(nil, nil)
		_, err := ResolveTarget(s, "missing")
		assert.Error(t, err, "expected not-found error")
	})

	t.Run("reports unknown workspace", func(t *testing.T) {
		t.Parallel()
		s := makeState(dupTargets, dupWorkspaces)
		_, err := ResolveTarget(s, "unknown/db")
		assert.Error(t, err, "expected unknown-workspace error")
	})
}

func TestProxyRejectsNilTarget(t *testing.T) {
	t.Parallel()
	err := Proxy(context.Background(), nil, "22")
	assert.ErrorContains(t, err, "nil target")
}

func TestProxyRejectsNoEndpoints(t *testing.T) {
	t.Parallel()
	target := &state.Target{ID: "t-1", Name: "prod"}
	err := Proxy(context.Background(), target, "22")
	assert.ErrorContains(t, err, "no endpoints configured")
}

func TestProxyReportsAllEndpointFailures(t *testing.T) {
	t.Parallel()
	target := &state.Target{
		ID:   "t-1",
		Name: "prod",
		// Unreachable addresses fail fast instead of hanging the test.
		Endpoints: []string{"127.0.0.1:1", "127.0.0.2:1"},
	}
	err := Proxy(context.Background(), target, "22")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all endpoints failed")
	assert.Contains(t, err.Error(), "127.0.0.1:1")
	assert.Contains(t, err.Error(), "127.0.0.2:1",
		"every endpoint failure must be reported")
}

func TestNormalizeEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
		sshPort  string
		want     string
		wantErr  bool
	}{
		{"empty endpoint", "", "22", "", true},
		{"hostname without port", "example.com", "22", "example.com:22", false},
		{"hostname with port", "example.com:2222", "22", "example.com:2222", false},
		{"IPv4 without port", "192.168.1.1", "22", "192.168.1.1:22", false},
		{"IPv4 with port", "192.168.1.1:2222", "22", "192.168.1.1:2222", false},
		{"IPv6 without port", "2001:db8::1", "22", "[2001:db8::1]:22", false},
		{"IPv6 with port", "[2001:db8::1]:2222", "22", "[2001:db8::1]:2222", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeEndpoint(tt.endpoint, tt.sshPort)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
