package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nk/internal/state"
)

func TestDestination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		arg     string
		user    string
		userSet bool
		port    string
		want    remote
	}{
		{
			name: "ssh alias keeps the flag user",
			arg:  "web-01",
			user: "root",
			port: "22",
			want: remote{host: "web-01", user: "root", port: "22"},
		},
		{
			name: "user@host sets the ssh user",
			arg:  "deploy@10.0.0.5",
			user: "root",
			port: "22",
			want: remote{host: "10.0.0.5", user: "deploy", port: "22"},
		},
		{
			name:    "an explicit user wins over the argument",
			arg:     "deploy@10.0.0.5",
			user:    "admin",
			userSet: true,
			port:    "22",
			want:    remote{host: "10.0.0.5", user: "admin", port: "22"},
		},
		{
			name: "port comes from the flag",
			arg:  "web-01",
			user: "root",
			port: "2222",
			want: remote{host: "web-01", user: "root", port: "2222"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, destination(tt.arg, tt.user, tt.userSet, tt.port))
		})
	}
}

func TestResolveWorkspace(t *testing.T) {
	t.Parallel()

	workspaces := []state.Workspace{{ID: "ws-1", Name: "acme"}, {ID: "ws-2", Name: "globex"}}
	several := &state.State{Workspaces: workspaces}
	single := &state.State{Workspaces: workspaces[:1]}

	tests := []struct {
		name    string
		state   *state.State
		ref     string
		want    string
		wantErr string
	}{
		{name: "by id", state: several, ref: "ws-2", want: "ws-2"},
		{name: "by name", state: several, ref: "acme", want: "ws-1"},
		{name: "the only workspace needs no flag", state: single, want: "ws-1"},
		{name: "unknown ref", state: several, ref: "nope", wantErr: `workspace "nope" not found`},
		{name: "several workspaces need a flag", state: several, wantErr: "pass --workspace: acme, globex"},
		{name: "no workspace at all", state: &state.State{}, wantErr: "do not belong to any workspace"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveWorkspace(tt.state, tt.ref)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.ID)
		})
	}
}

func TestResolveCA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cas        []state.CA
		ref        string
		wantID     string
		wantSource string
		wantErr    string
	}{
		{
			name:       "default when no flag",
			cas:        []state.CA{{ID: "ca-1", WorkspaceID: "ws-1", Name: "main", Default: true}},
			wantID:     "ca-1",
			wantSource: "default",
		},
		{
			name:       "the only ca needs no flag",
			cas:        []state.CA{{ID: "ca-1", WorkspaceID: "ws-1", Name: "main"}},
			wantID:     "ca-1",
			wantSource: "only ca",
		},
		{
			name: "by name",
			cas: []state.CA{
				{ID: "ca-1", WorkspaceID: "ws-1", Name: "main"},
				{ID: "ca-2", WorkspaceID: "ws-1", Name: "burst"},
			},
			ref:        "burst",
			wantID:     "ca-2",
			wantSource: "selected",
		},
		{
			name:    "no ca in the workspace",
			cas:     []state.CA{{ID: "ca-9", WorkspaceID: "ws-2", Name: "other", Default: true}},
			wantErr: "no certificate authority",
		},
		{
			name: "several cas and none default",
			cas: []state.CA{
				{ID: "ca-1", WorkspaceID: "ws-1", Name: "main"},
				{ID: "ca-2", WorkspaceID: "ws-1", Name: "burst"},
			},
			wantErr: "pass --ca",
		},
		{
			name:    "ref from another workspace is not a candidate",
			cas:     []state.CA{{ID: "ca-9", WorkspaceID: "ws-2", Name: "other"}},
			ref:     "other",
			wantErr: `certificate authority "other" not found`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &state.State{CAs: tt.cas}
			got, source, err := resolveCA(s, "ws-1", tt.ref)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, got.ID)
			assert.Equal(t, tt.wantSource, source)
		})
	}
}

func TestTargetLookup(t *testing.T) {
	t.Parallel()

	s := &state.State{Targets: []state.Target{
		{ID: "t-1", WorkspaceID: "ws-1", Name: "web-01", Endpoints: []string{"10.0.0.5"}},
		{ID: "t-2", WorkspaceID: "ws-2", Name: "web-02", Endpoints: []string{"10.0.0.6"}},
		{ID: "t-3", WorkspaceID: "ws-1", Name: "daemoned", Endpoints: []string{"10.0.0.7"}, DaemonID: "d-1"},
	}}

	// A repeated sync must find the machine it registered before.
	assert.Equal(t, "t-1", targetByEndpoint(s, "ws-1", "10.0.0.5").ID)
	assert.Equal(t, "t-2", targetByEndpoint(s, "ws-2", "10.0.0.6").ID)
	assert.Nil(t, targetByEndpoint(s, "ws-1", "10.0.0.6"), "another workspace's address is not a match")
	assert.Nil(t, targetByEndpoint(s, "ws-1", "10.0.0.7"), "a daemon target syncs itself")
	assert.Nil(t, targetByEndpoint(s, "ws-1", "10.9.9.9"), "an unknown address has no target")

	assert.Equal(t, "t-1", targetByName(s, "ws-1", "web-01").ID)
	assert.Nil(t, targetByName(s, "ws-1", "web-02"), "names are scoped to the workspace")
}
