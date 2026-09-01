package ssh

import (
	"fmt"
	"strings"

	"github.com/nokku-sh/nk/internal/fsutil"
	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

func GenerateSSHConfig(st *state.State) error {
	// Workspace ID -> name, for qualifying targets whose name collides
	// across workspaces.
	wsNames := make(map[string]string, len(st.Workspaces))
	for _, w := range st.Workspaces {
		wsNames[w.ID] = w.Name
	}

	// Count valid targets per name so duplicated names get a qualified host.
	nameCount := make(map[string]int, len(st.Targets))
	for _, t := range st.Targets {
		if validTarget(t) {
			nameCount[t.Name]++
		}
	}

	var buf strings.Builder
	buf.WriteString("# Managed by Nokku\n")
	buf.WriteString("# Do not edit manually. Changes will be overwritten.\n\n")

	for _, t := range st.Targets {
		if !validTarget(t) {
			continue
		}

		host := t.Name
		if nameCount[t.Name] > 1 {
			ws := wsNames[t.WorkspaceID]
			if ws == "" || !safeConfigToken(ws) || strings.Contains(ws, "/") {
				ws = t.WorkspaceID
			}
			host = ws + "/" + t.Name
		}

		fmt.Fprintf(&buf, "Host %s\n", host)
		fmt.Fprintf(&buf, "    User %s\n", t.Principals[0].Username)
		fmt.Fprintf(&buf, "    ProxyCommand nk proxy %%h %%p\n")
		fmt.Fprintf(&buf, "    CertificateFile %s\n", paths.SSHCertificate(t.CAID))
		if TPMKeyActive() {
			// The private key lives in the TPM: point IdentityFile at the
			// public key so ssh looks the private key up in the agent.
			fmt.Fprintf(&buf, "    IdentityFile %s\n", paths.PubKeyFile())
			fmt.Fprintf(&buf, "    IdentityAgent %s\n", paths.AgentSocket())
		} else {
			fmt.Fprintf(&buf, "    IdentityFile %s\n", paths.KeyFile())
		}
		fmt.Fprintf(&buf, "    UserKnownHostsFile %s\n", paths.KnownHostsPath())
		fmt.Fprintf(&buf, "    HostKeyAlias %s\n", t.ID)
		buf.WriteString("    IdentitiesOnly yes\n")
		buf.WriteString("    PubkeyAuthentication yes\n")
		buf.WriteString("    PasswordAuthentication no\n")
		buf.WriteString("    StrictHostKeyChecking yes\n")
		buf.WriteString("    ConnectTimeout 30\n")
		buf.WriteString("    ServerAliveInterval 60\n")
		buf.WriteString("    ServerAliveCountMax 3\n")
		buf.WriteString("    LogLevel ERROR\n")
		buf.WriteString("\n")
	}

	return fsutil.WriteIfChanged(paths.SSHConfigFile(), []byte(buf.String()), 0o600)
}

// validTarget reports whether t is complete and safe to emit as an SSH host.
func validTarget(t state.Target) bool {
	return t.ID != "" && t.Name != "" && t.CAID != "" && len(t.Principals) > 0 &&
		safeConfigToken(t.Name) && safeConfigToken(t.Principals[0].Username)
}

func GenerateKnownHosts(st *state.State) error {
	var buf strings.Builder
	buf.WriteString("# Managed by Nokku\n")
	buf.WriteString("# Do not edit manually. Changes will be overwritten.\n\n")
	for _, ca := range st.CAs {
		fmt.Fprintf(&buf, "@cert-authority * %s\n", strings.TrimSpace(ca.PublicKey))
	}
	return fsutil.WriteIfChanged(paths.KnownHostsPath(), []byte(buf.String()), 0o600)
}

// safeConfigToken reports whether s is safe to embed in a generated SSH
// config line: control characters are line-structure breaking and must
// never reach the file.
func safeConfigToken(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
