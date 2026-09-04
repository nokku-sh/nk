package ssh

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

func TestGenerateSSHConfig(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		Targets: []state.Target{
			{
				ID:         "t-1",
				Name:       "prod",
				CAID:       "ca-1",
				Principals: []state.Principal{{Username: "alice"}},
			},
			{
				ID:         "t-2",
				Name:       "staging",
				CAID:       "ca-2",
				Principals: []state.Principal{{Username: "bob"}},
			},
			// Incomplete targets must be skipped.
			{
				ID:         "t-3",
				Name:       "no-ca",
				CAID:       "",
				Principals: []state.Principal{{Username: "c"}},
			},
			{ID: "t-4", Name: "no-principals", CAID: "ca-3"},
			{ID: "t-5", Name: "", CAID: "ca-3", Principals: []state.Principal{{Username: "e"}}},
		},
	}

	require.NoError(t, GenerateSSHConfig(st))

	content, err := os.ReadFile(paths.SSHConfigFile())
	require.NoError(t, err)

	for _, want := range []string{
		"# Managed by Nokku\n",
		"Host prod\n",
		"    User alice\n",
		"    ProxyCommand nk proxy %h %p\n",
		"    CertificateFile " + paths.SSHCertificate("ca-1") + "\n",
		"    IdentityFile " + paths.KeyFile() + "\n",
		"    HostKeyAlias t-1\n",
		"    IdentitiesOnly yes\n",
		"    PasswordAuthentication no\n",
		"    StrictHostKeyChecking yes\n",
		"    ConnectTimeout 30\n",
		"Host staging\n",
		"    User bob\n",
	} {
		assert.Contains(t, string(content), want)
	}
	for _, forbidden := range []string{"no-ca", "no-principals", "t-3", "t-4"} {
		assert.NotContains(t, string(content), forbidden)
	}
}

func TestGenerateSSHConfigTPMIdentity(t *testing.T) {
	setupSSHDir(t)
	// A TPM identity is detected by the absence of a private key file while
	// the public key exists. ssh then uses the agent for the private key.
	require.NoError(t, os.WriteFile(paths.PubKeyFile(), []byte("ssh-ed25519 AAAA\n"), 0o600))

	st := &state.State{
		Targets: []state.Target{
			{
				ID:         "t-1",
				Name:       "prod",
				CAID:       "ca-1",
				Principals: []state.Principal{{Username: "alice"}},
			},
		},
	}
	require.NoError(t, GenerateSSHConfig(st))

	content, err := os.ReadFile(paths.SSHConfigFile())
	require.NoError(t, err)
	assert.Contains(t, string(content), "    IdentityFile "+paths.PubKeyFile()+"\n",
		"TPM identity must point IdentityFile at the public key")
	assert.Contains(t, string(content), "    IdentityAgent "+paths.AgentSocket()+"\n",
		"TPM identity must set IdentityAgent")
}

func TestGenerateSSHConfigDisambiguatesDuplicateNames(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		Workspaces: []state.Workspace{
			{ID: "ws-1", Name: "staging"},
			{ID: "ws-2", Name: "production"},
		},
		Targets: []state.Target{
			{ID: "t-1", Name: "db", WorkspaceID: "ws-1", CAID: "ca-1",
				Principals: []state.Principal{{Username: "alice"}}},
			{ID: "t-2", Name: "db", WorkspaceID: "ws-2", CAID: "ca-2",
				Principals: []state.Principal{{Username: "bob"}}},
			{ID: "t-3", Name: "unique", WorkspaceID: "ws-1", CAID: "ca-1",
				Principals: []state.Principal{{Username: "carol"}}},
		},
	}

	require.NoError(t, GenerateSSHConfig(st))
	content, err := os.ReadFile(paths.SSHConfigFile())
	require.NoError(t, err)

	assert.Contains(t, string(content), "Host staging/db\n",
		"expected workspace-qualified host for duplicate name")
	assert.Contains(t, string(content), "Host production/db\n",
		"expected workspace-qualified host for duplicate name")
	assert.Contains(t, string(content), "Host unique\n",
		"expected bare host for unique name")
	assert.NotContains(t, string(content), "\nHost db\n",
		"duplicate bare name must not be emitted")
}

func TestGenerateSSHConfigRejectsControlCharacters(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		Targets: []state.Target{
			{
				ID:         "t-1",
				Name:       "prod\n    ProxyCommand curl http://evil",
				CAID:       "ca-1",
				Principals: []state.Principal{{Username: "alice"}},
			},
			{
				ID:   "t-2",
				Name: "ok",
				CAID: "ca-1",
				Principals: []state.Principal{
					{Username: "alice\n    ProxyCommand curl http://evil2"},
				},
			},
		},
	}

	require.NoError(t, GenerateSSHConfig(st))
	content, err := os.ReadFile(paths.SSHConfigFile())
	require.NoError(t, err)

	for _, forbidden := range []string{"curl http://evil", "evil2", "ProxyCommand"} {
		assert.NotContains(t, string(content), forbidden,
			"injected content reached the generated config")
	}
}

func TestGenerateKnownHosts(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		CAs: []state.CA{
			{ID: "ca-1", Name: "Production CA", PublicKey: "ssh-ed25519 AAAACa1== production"},
			{ID: "ca-2", Name: "Staging CA", PublicKey: "  ssh-rsa AAAACa2== staging\n"},
		},
		Targets: []state.Target{
			{ID: "t-1", Name: "prod", CAID: "ca-1"},
			{ID: "t-2", Name: "stage", CAID: "ca-2"},
			{ID: "t-3", Name: "no-ca"},
			{ID: "t-4", Name: "orphan", CAID: "ca-missing"},
		},
	}

	require.NoError(t, GenerateKnownHosts(st))
	content, err := os.ReadFile(paths.KnownHostsPath())
	require.NoError(t, err)

	// Trust is scoped to the target ID (the HostKeyAlias in the generated
	// config), never a global "*".
	assert.Contains(t, string(content), "@cert-authority t-1 ssh-ed25519 AAAACa1== production\n")
	assert.Contains(t, string(content), "@cert-authority t-2 ssh-rsa AAAACa2== staging\n")
	assert.NotContains(t, string(content), "@cert-authority *",
		"known_hosts must not trust a CA for every host")
	assert.NotContains(t, string(content), "t-3",
		"target without a CA must not get a known_hosts line")
	assert.NotContains(t, string(content), "t-4",
		"target with an unknown CA must not get a known_hosts line")
}

func TestSafeConfigToken(t *testing.T) {
	for _, ok := range []string{"prod", "prod-us-1", "staging", "my host", "ünïcode"} {
		assert.True(t, safeConfigToken(ok), "safeConfigToken(%q) = false, want true", ok)
	}
	for _, bad := range []string{"a\nb", "a\rb", "a\tb", "a\x00b", "a\x1bb", "a\x7fb"} {
		assert.False(t, safeConfigToken(bad), "safeConfigToken(%q) = true, want false", bad)
	}
}
