package ssh

import (
	"fmt"
	"strings"

	"github.com/nokku-sh/mon/fsutil"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

func GenerateSSHConfig(st *state.State) error {
	wsNames := make(map[string]string, len(st.Workspaces))
	for _, w := range st.Workspaces {
		wsNames[w.ID] = w.Name
	}

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

		certPath, err := paths.SSHCertificate(t.CAID)
		if err != nil {
			continue
		}

		host := t.Name
		if nameCount[t.Name] > 1 {
			ws := wsNames[t.WorkspaceID]
			if ws == "" || !safeConfigToken(ws) || strings.Contains(ws, "/") {
				ws = t.WorkspaceID
			}
			// The workspace id lands in the Host line, so it is held to the
			// same rule as the target name.
			if ws == "" || !safeConfigToken(ws) || strings.Contains(ws, "/") {
				continue
			}
			host = ws + "/" + t.Name
		}

		// The private key lives in the TPM or in the wrapped signer state,
		// so IdentityFile points at the public half and the agent supplies
		// the signature. Only the first granted account is emitted, others
		// still work with `ssh <user>@<host>`.
		fmt.Fprintf(&buf, `Host %s
    User %s
    ProxyCommand nk proxy %%h %%p
    CertificateFile %s
    IdentityFile %s
    IdentityAgent %s
    UserKnownHostsFile %s
    HostKeyAlias %s
    IdentitiesOnly yes
    PubkeyAuthentication yes
    PasswordAuthentication no
    StrictHostKeyChecking yes
    ConnectTimeout 30
    ServerAliveInterval 60
    ServerAliveCountMax 3
    LogLevel ERROR

`, host, t.Usernames[0], certPath, paths.PubKeyFile(),
			paths.AgentSocket(), paths.KnownHostsPath(), t.ID)
	}

	return fsutil.WriteIfChanged(paths.SSHConfigFile(), []byte(buf.String()), 0o600)
}

func GenerateKnownHosts(st *state.State) error {
	var buf strings.Builder
	buf.WriteString("# Managed by Nokku\n")
	buf.WriteString("# Do not edit manually. Changes will be overwritten.\n\n")
	// Scope trust to the target ID, which is the HostKeyAlias in the generated
	// ssh config, never a global "*".
	for _, t := range st.Targets {
		if t.ID == "" || !safeConfigToken(t.ID) {
			continue
		}
		if t.DaemonID == "" {
			// A manual target presents its own host key, not one signed by the
			// CA, so an @cert-authority line can never match it. Pin the raw
			// key instead.
			key := strings.TrimSpace(t.HostPublicKey)
			if key == "" || !safeKeyLine(key) {
				continue
			}
			fmt.Fprintf(&buf, "%s %s\n", t.ID, key)
			continue
		}
		if t.CAID == "" {
			continue
		}
		ca := st.CAByID(t.CAID)
		if ca == nil {
			continue
		}
		key := strings.TrimSpace(ca.PublicKey)
		if key == "" || !safeKeyLine(key) {
			continue
		}
		fmt.Fprintf(&buf, "@cert-authority %s %s\n", t.ID, key)
	}
	return fsutil.WriteIfChanged(paths.KnownHostsPath(), []byte(buf.String()), 0o600)
}

// validTarCAByIDts whether t is complete and safe to emit as an SSH host.
func validTarget(t state.Target) bool {
	return t.ID != "" && t.Name != "" && t.CAID != "" && len(t.Usernames) > 0 &&
		safeConfigToken(t.Name) && safeConfigToken(t.Usernames[0]) &&
		safeConfigToken(t.ID) && safeConfigToken(t.CAID)
}

// unsafeConfigChars lists characters that may not appear in a value emitted into
// a generated ssh config or known_hosts line. The wildcard characters would
// widen a Host or known_hosts pattern to hosts the target does not own, the rest
// are shell metacharacters in files that ssh and other tools read.
const unsafeConfigChars = " #\"'`$&|;<>(){}[]*?!~\\"

// safeConfigToken reports whether s is safe as a single token in a generated
// SSH config or known_hosts line.
func safeConfigToken(s string) bool {
	if s == "" || strings.ContainsAny(s, unsafeConfigChars) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// safeKeyLine reports whether s is safe as a key field, where spaces are part of
// the format. Only control characters can break the line.
func safeKeyLine(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
