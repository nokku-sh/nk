package ssh

import (
	"os"
	"strings"
	"testing"

	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/util"
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

	if err := GenerateSSHConfig(st); err != nil {
		t.Fatalf("GenerateSSHConfig: %v", err)
	}

	data, err := os.ReadFile(util.SSHConfigFile())
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	content := string(data)

	for _, want := range []string{
		"# Managed by Nokku\n",
		"Host prod\n",
		"    User alice\n",
		"    ProxyCommand nk proxy %h %p\n",
		"    CertificateFile " + util.SSHCertificate("ca-1") + "\n",
		"    IdentityFile " + util.KeyFile() + "\n",
		"    HostKeyAlias t-1\n",
		"    IdentitiesOnly yes\n",
		"    PasswordAuthentication no\n",
		"    StrictHostKeyChecking yes\n",
		"    ConnectTimeout 30\n",
		"Host staging\n",
		"    User bob\n",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("generated config missing %q", want)
		}
	}
	for _, forbidden := range []string{"no-ca", "no-principals", "t-3", "t-4"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("generated config contains skipped target %q", forbidden)
		}
	}
}

func TestGenerateSSHConfigTPMIdentity(t *testing.T) {
	setupSSHDir(t)
	// A TPM identity is detected by the absence of a private key file while
	// the public key exists. ssh then uses the agent for the private key.
	if err := os.WriteFile(util.PubKeyFile(), []byte("ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}

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
	if err := GenerateSSHConfig(st); err != nil {
		t.Fatalf("GenerateSSHConfig: %v", err)
	}

	data, err := os.ReadFile(util.SSHConfigFile())
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "    IdentityFile "+util.PubKeyFile()+"\n") {
		t.Errorf("TPM identity must point IdentityFile at the public key")
	}
	if !strings.Contains(content, "    IdentityAgent "+util.AgentSocket()+"\n") {
		t.Errorf("TPM identity must set IdentityAgent")
	}
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

	if err := GenerateSSHConfig(st); err != nil {
		t.Fatalf("GenerateSSHConfig: %v", err)
	}
	data, err := os.ReadFile(util.SSHConfigFile())
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "Host staging/db\n") {
		t.Errorf("expected workspace-qualified host for duplicate name, got:\n%s", content)
	}
	if !strings.Contains(content, "Host production/db\n") {
		t.Errorf("expected workspace-qualified host for duplicate name, got:\n%s", content)
	}
	if !strings.Contains(content, "Host unique\n") {
		t.Errorf("expected bare host for unique name, got:\n%s", content)
	}
	if strings.Contains(content, "\nHost db\n") {
		t.Errorf("duplicate bare name must not be emitted, got:\n%s", content)
	}
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

	if err := GenerateSSHConfig(st); err != nil {
		t.Fatalf("GenerateSSHConfig: %v", err)
	}
	data, err := os.ReadFile(util.SSHConfigFile())
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	content := string(data)

	for _, forbidden := range []string{"curl http://evil", "evil2", "ProxyCommand"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("injected content reached the generated config: %q", forbidden)
		}
	}
}

func TestGenerateKnownHosts(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		CAs: []state.CA{
			{ID: "ca-1", Name: "Production CA", PublicKey: "ssh-ed25519 AAAACa1== production"},
			{ID: "ca-2", Name: "Staging CA", PublicKey: "  ssh-rsa AAAACa2== staging\n"},
		},
	}

	if err := GenerateKnownHosts(st); err != nil {
		t.Fatalf("GenerateKnownHosts: %v", err)
	}
	data, err := os.ReadFile(util.KnownHostsPath())
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "@cert-authority * ssh-ed25519 AAAACa1== production\n") {
		t.Errorf("known_hosts missing trimmed CA 1 line, got:\n%s", content)
	}
	if !strings.Contains(content, "@cert-authority * ssh-rsa AAAACa2== staging\n") {
		t.Errorf("known_hosts missing trimmed CA 2 line, got:\n%s", content)
	}
}

func TestSafeConfigToken(t *testing.T) {
	for _, ok := range []string{"prod", "prod-us-1", "staging", "my host", "ünïcode"} {
		if !safeConfigToken(ok) {
			t.Errorf("safeConfigToken(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"a\nb", "a\rb", "a\tb", "a\x00b", "a\x1bb", "a\x7fb"} {
		if safeConfigToken(bad) {
			t.Errorf("safeConfigToken(%q) = true, want false", bad)
		}
	}
}
