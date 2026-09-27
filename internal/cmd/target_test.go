package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nk/internal/state"
)

func testState() *state.State {
	return &state.State{
		Workspaces: []state.Workspace{{ID: "ws-1", Name: "prod"}, {ID: "ws-2", Name: "lab"}},
		CAs: []state.CA{
			{ID: "ca-1", WorkspaceID: "ws-1", Name: "main", Default: true},
			{ID: "ca-2", WorkspaceID: "ws-1", Name: "legacy"},
			{ID: "ca-3", WorkspaceID: "ws-2", Name: "lab"},
		},
		Targets: []state.Target{
			{ID: "t-1", WorkspaceID: "ws-1", Name: "web", Endpoints: []string{"10.0.0.5:2222"}},
			{ID: "t-2", WorkspaceID: "ws-1", Name: "db", DaemonID: "d", Endpoints: []string{"10.0.0.6"}},
			{ID: "t-3", WorkspaceID: "ws-1", Name: "dup"},
			{ID: "t-4", WorkspaceID: "ws-2", Name: "dup"},
		}}
}

func TestFindTarget(t *testing.T) {
	t.Parallel()
	s := testState()

	got, err := findTarget(s, "", "web")
	require.NoError(t, err)
	assert.Equal(t, "t-1", got.ID, "by name")

	got, err = findTarget(s, "", "10.0.0.5")
	require.NoError(t, err)
	assert.Equal(t, "t-1", got.ID, "by endpoint host, ignoring its port")

	got, err = findTarget(s, "", "10.0.0.9")
	require.NoError(t, err)
	assert.Nil(t, got, "an unknown host is a new target")

	_, err = findTarget(s, "", "db")
	require.ErrorContains(t, err, "daemon")

	_, err = findTarget(s, "", "dup")
	require.ErrorContains(t, err, "--workspace")
	got, err = findTarget(s, "lab", "dup")
	require.NoError(t, err)
	assert.Equal(t, "t-4", got.ID)
}

func TestResolveWorkspace(t *testing.T) {
	t.Parallel()
	s := testState()

	_, err := resolveWorkspace(s, "")
	require.ErrorContains(t, err, "prod, lab")
	ws, err := resolveWorkspace(s, "lab")
	require.NoError(t, err)
	assert.Equal(t, "ws-2", ws.ID)
	_, err = resolveWorkspace(s, "nope")
	require.Error(t, err)

	s.Workspaces = s.Workspaces[:1]
	ws, err = resolveWorkspace(s, "")
	require.NoError(t, err)
	assert.Equal(t, "ws-1", ws.ID, "a single workspace needs no flag")
}

func TestResolveCA(t *testing.T) {
	t.Parallel()
	s := testState()

	ca, err := resolveCA(s, "ws-1", "")
	require.NoError(t, err)
	assert.Equal(t, "ca-1", ca.ID, "the default wins")

	ca, err = resolveCA(s, "ws-1", "legacy")
	require.NoError(t, err)
	assert.Equal(t, "ca-2", ca.ID)

	ca, err = resolveCA(s, "ws-2", "")
	require.NoError(t, err)
	assert.Equal(t, "ca-3", ca.ID, "the only CA needs no flag")

	_, err = resolveCA(s, "ws-2", "main")
	require.Error(t, err, "a CA from another workspace is not found")

	s.CAs[0].Default = false
	_, err = resolveCA(s, "ws-1", "")
	require.ErrorContains(t, err, "--ca")
}

func TestEndpointRemote(t *testing.T) {
	t.Parallel()
	assert.Equal(t, remote{host: "10.0.0.5", port: "2222"}, endpointRemote("10.0.0.5:2222", ""))
	assert.Equal(t, remote{host: "10.0.0.5", port: "22"}, endpointRemote("10.0.0.5:2222", "22"))
	assert.Equal(t, remote{host: "web.lan"}, endpointRemote("web.lan", ""))
	assert.Equal(t, "ssh -p 2222 root@10.0.0.5", remote{host: "10.0.0.5", port: "2222"}.String())
	assert.Equal(t, "ssh root@web.lan", remote{host: "web.lan"}.String())
}
