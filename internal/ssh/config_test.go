package ssh

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

func TestRenderSSHConfig(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		Workspaces: []state.Workspace{{ID: "ws-1", Name: "staging"}, {ID: "ws-2", Name: "prod uction"}},
		Targets: []state.Target{
			{ID: "t-1", Name: "web", CAID: "ca-1", Usernames: []string{"alice", "bob"}},
			{ID: "t-2", Name: "db", WorkspaceID: "ws-1", CAID: "ca-1", Usernames: []string{"alice"}},
			{ID: "t-3", Name: "db", WorkspaceID: "ws-2", CAID: "ca-1", Usernames: []string{"alice"}},
			{ID: "t-4", Name: "no-users", CAID: "ca-1"},
			{ID: "t-5", Name: "prod\n    ProxyCommand curl evil", CAID: "ca-1", Usernames: []string{"a"}},
			{ID: "t-6", Name: "ok", CAID: "ca-1", Usernames: []string{"a\n    ProxyCommand curl evil"}},
			{ID: "t-7", Name: "a/b", CAID: "ca-1", Usernames: []string{"a"}},
		}}
	out := string(renderSSHConfig(st, "nk"))

	for _, want := range []string{
		"Match originalhost web exec \"nk prepare t-1\"\n\nHost web\n    User alice\n    ProxyCommand nk proxy t-1 %p\n    HostKeyAlias t-1\n",
		"    CertificateFile " + configValue(paths.SSHCertificate("ca-1")) + "\n",
		"    IdentityAgent " + configValue(paths.AgentSocket()) + "\n",
		"Host staging/db\n",
		"Host ws-2/db\n", // an unsafe workspace name falls back to its id
	} {
		assert.Contains(t, out, want)
	}
	for _, forbidden := range []string{"no-users", "curl evil", "a/b", "\nHost db\n"} {
		assert.NotContains(t, out, forbidden)
	}
}

func TestConfigValueQuotesPaths(t *testing.T) {
	t.Parallel()
	assert.Equal(t, `"/Users/Jane Doe/.config/nk/ssh_config"`, configValue("/Users/Jane Doe/.config/nk/ssh_config"))
	assert.Equal(t, `"C:\\Users\\Jane Doe\\x"`, configValue(`C:\Users\Jane Doe\x`))
	assert.Equal(t, `"\\\\.\\pipe\\nk-agent"`, configValue(`\\.\pipe\nk-agent`))
	assert.Equal(t, `"\"C:\\Program Files\\nk.exe\" prepare t-1"`, configValue(`"C:\Program Files\nk.exe" prepare t-1`))
}

func TestRenderKnownHosts(t *testing.T) {
	t.Parallel()
	st := &state.State{
		CAs: []state.CA{
			{
				ID: "ca-1", PublicKey: "ssh-ed25519 AAAACa1== production",
				PreviousPublicKey: "ssh-ed25519 AAAAOld1==", PreviousTrustedUntil: time.Now().Add(time.Hour),
			},
			{
				ID: "ca-3", PublicKey: "ssh-ed25519 AAAACa3==",
				PreviousPublicKey: "ssh-ed25519 AAAAOld3==", PreviousTrustedUntil: time.Now().Add(-time.Hour),
			},
			{ID: "ca-2", PublicKey: "ssh-ed25519 AAAA==\nHost *\n    ProxyCommand curl evil"},
		},
		Targets: []state.Target{
			{ID: "t-1", CAID: "ca-1", DaemonID: "d-1"},
			{ID: "t-2", CAID: "ca-2", DaemonID: "d-2"},
			{ID: "t-3", CAID: "ca-1", HostPublicKey: "ssh-ed25519 AAAAhost== host"},
			{ID: "t-4", CAID: "ca-1"},
			{ID: "t-5", CAID: "ca-1", DaemonID: "d-5", HostPublicKey: "ssh-ed25519 AAAAstray"},
			{ID: "t-6", CAID: "ca-3", DaemonID: "d-6"},
		}}
	out := string(renderKnownHosts(st))

	assert.Contains(t, out, "@cert-authority t-1 ssh-ed25519 AAAACa1== production\n")
	assert.Contains(
		t,
		out,
		"@cert-authority t-1 ssh-ed25519 AAAAOld1==\n",
		"a replaced key stays trusted until its deadline",
	)
	assert.Contains(t, out, "@cert-authority t-6 ssh-ed25519 AAAACa3==\n")
	assert.NotContains(t, out, "AAAAOld3", "a replaced key past its deadline is dropped")
	assert.Contains(t, out, "t-3 ssh-ed25519 AAAAhost== host\n")
	assert.NotContains(t, out, "@cert-authority t-3", "manual targets are pinned, not CA trusted")
	assert.NotContains(t, out, "t-4", "nothing to pin without a host key")
	assert.NotContains(t, out, "AAAAstray", "daemon targets are never pinned by a raw key")
	assert.NotContains(t, out, "curl evil")
}

func TestInclude(t *testing.T) {
	setupSSHDir(t)
	cfg := paths.SSHUserConfig()

	require.NoError(t, ensureInclude(), "a missing ~/.ssh/config is created")
	data, err := os.ReadFile(cfg)
	require.NoError(t, err)
	assert.True(t, HasInclude(data))

	original := "Host own\n    HostName example.com\n"
	require.NoError(t, os.WriteFile(cfg, []byte(original), 0o600))
	require.NoError(t, ensureInclude())
	require.NoError(t, ensureInclude())
	data, err = os.ReadFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, includeLine()+"\n\n"+original, string(data), "include goes on top, once")

	require.NoError(t, RemoveInclude())
	data, err = os.ReadFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, original, string(data))
}

func TestIncludeKeepsSymlink(t *testing.T) {
	setupSSHDir(t)
	target := filepath.Join(t.TempDir(), "dotfiles-ssh-config")
	require.NoError(t, os.WriteFile(target, []byte("Host own\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.SSHUserConfig()), 0o700))
	if err := os.Symlink(target, paths.SSHUserConfig()); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	require.NoError(t, ensureInclude())
	fi, err := os.Lstat(paths.SSHUserConfig())
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink, "the dotfile link must survive")
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.True(t, HasInclude(data))
}

func TestNKCommandIsAbsolute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows paths fall back to a PATH lookup")
	}
	self, err := os.Executable()
	require.NoError(t, err)
	assert.Equal(t, self, nkCommand(), "ProxyCommand must name this binary")
}
