package ssh

import (
	"fmt"
	"strings"

	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/util"
)

func GenerateSSHConfig(st *state.State) error {
	var buf strings.Builder
	buf.WriteString("# Managed by Nokku\n")
	buf.WriteString("# Do not edit manually. Changes will be overwritten.\n\n")

	for _, t := range st.Targets {
		if t.ID == "" || t.Name == "" || t.CAID == "" || len(t.Principals) == 0 {
			continue
		}
		if !safeConfigToken(t.Name) || !safeConfigToken(t.Principals[0].Username) {
			continue
		}

		fmt.Fprintf(&buf, "Host %s\n", t.Name)
		fmt.Fprintf(&buf, "    User %s\n", t.Principals[0].Username)
		fmt.Fprintf(&buf, "    ProxyCommand nk proxy %%h %%p\n")
		fmt.Fprintf(&buf, "    CertificateFile %s\n", util.Certificate(t.CAID))
		if TPMKeyActive() {
			// The private key lives in the TPM: point IdentityFile at the
			// public key so ssh looks the private key up in the agent.
			fmt.Fprintf(&buf, "    IdentityFile %s\n", util.PubKeyFile())
			fmt.Fprintf(&buf, "    IdentityAgent %s\n", util.AgentSocket())
		} else {
			fmt.Fprintf(&buf, "    IdentityFile %s\n", util.KeyFile())
		}
		fmt.Fprintf(&buf, "    UserKnownHostsFile %s\n", util.KnownHostsPath())
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

	return util.WriteIfChanged(util.SSHConfigFile(), []byte(buf.String()), 0o600)
}

func GenerateKnownHosts(st *state.State) error {
	var buf strings.Builder
	buf.WriteString("# Managed by Nokku\n")
	buf.WriteString("# Do not edit manually. Changes will be overwritten.\n\n")
	for _, ca := range st.CAs {
		fmt.Fprintf(&buf, "@cert-authority * %s\n", strings.TrimSpace(ca.PublicKey))
	}
	return util.WriteIfChanged(util.KnownHostsPath(), []byte(buf.String()), 0o600)
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
