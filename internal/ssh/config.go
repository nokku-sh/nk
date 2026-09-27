package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

const header = "# Managed by Nokku. nk regenerates this file, do not edit it.\n\n"

// unsafeChars may not appear in a target or user name emitted into ssh_config.
// Wildcards and lists would widen a Host pattern to hosts the target does not
// own, / is the workspace separator, the rest are shell metacharacters.
const unsafeChars = " ,/#\"'`$&|;<>(){}[]*?!~\\%="

// WriteConfigs regenerates ssh_config and known_hosts from the snapshot and
// makes sure ~/.ssh/config includes them.
func WriteConfigs(st *state.State) error {
	if err := fsutil.WriteIfChanged(paths.SSHConfigFile(), renderSSHConfig(st), 0o600); err != nil {
		return err
	}
	if err := fsutil.WriteIfChanged(paths.KnownHostsPath(), renderKnownHosts(st), 0o600); err != nil {
		return err
	}
	return EnsureInclude()
}

func renderSSHConfig(st *state.State) []byte {
	nameCount := make(map[string]int)
	for _, t := range st.Targets {
		if usable(t) {
			nameCount[t.Name]++
		}
	}

	var b bytes.Buffer
	b.WriteString(header)
	for _, t := range st.Targets {
		if !usable(t) {
			continue
		}
		host := t.Name
		if nameCount[t.Name] > 1 {
			ws := st.WorkspaceName(t.WorkspaceID)
			if !safeToken(ws) {
				ws = t.WorkspaceID
			}
			host = ws + "/" + t.Name
		}

		// The private key lives in the TPM or the wrapped signer state, so
		// IdentityFile is the public half and the agent signs. Only the first
		// account is the default, others work with ssh <user>@<host>. The
		// proxy gets the target id, since ssh lowercases %h.
		fmt.Fprintf(&b, `Host %s
    User %s
    ProxyCommand nk proxy %s %%p
    HostKeyAlias %s
    CertificateFile %s
    IdentityFile %s
    IdentityAgent %s
    UserKnownHostsFile %s
    IdentitiesOnly yes
    PasswordAuthentication no
    StrictHostKeyChecking yes
    ServerAliveInterval 60
    LogLevel ERROR

`, host, t.Usernames[0], t.ID, t.ID,
			configValue(paths.SSHCertificate(t.CAID)), configValue(paths.PubKeyFile()),
			configValue(paths.AgentSocket()), configValue(paths.KnownHostsPath()))
	}
	return b.Bytes()
}

// renderKnownHosts scopes trust to the target id, which is the HostKeyAlias
// in ssh_config, never a global "*".
func renderKnownHosts(st *state.State) []byte {
	var b bytes.Buffer
	b.WriteString(header)
	for _, t := range st.Targets {
		if t.Manual() {
			// A manual host presents its own key, not a CA-signed one.
			if key := strings.TrimSpace(t.HostPublicKey); safeLine(key) {
				fmt.Fprintf(&b, "%s %s\n", t.ID, key)
			}
			continue
		}
		if ca := st.CAByID(t.CAID); ca != nil {
			if key := strings.TrimSpace(ca.PublicKey); safeLine(key) {
				fmt.Fprintf(&b, "@cert-authority %s %s\n", t.ID, key)
			}
		}
	}
	return b.Bytes()
}

func usable(t state.Target) bool {
	return len(t.Usernames) > 0 && safeToken(t.Name) && safeToken(t.Usernames[0])
}

func safeToken(s string) bool {
	return s != "" && !strings.ContainsAny(s, unsafeChars) && safeLine(s)
}

// safeLine rejects control characters, the only thing that can break out of
// a key line.
func safeLine(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// configValue quotes a path for ssh_config. Quotes cover spaces, and ssh
// unescapes doubled backslashes, which Windows paths and pipes need.
func configValue(p string) string {
	return `"` + strings.ReplaceAll(p, `\`, `\\`) + `"`
}

// IncludeLine is the line nk puts on top of ~/.ssh/config.
func IncludeLine() string {
	return "Include " + configValue(paths.SSHConfigFile())
}

// EnsureInclude prepends IncludeLine to ~/.ssh/config when it is missing. It
// goes on top because an Include after a Host line would be scoped to it.
func EnsureInclude() error {
	path := userConfig()
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read ssh config: %w", err)
	}
	if HasInclude(data) {
		return nil
	}
	out := append([]byte(IncludeLine()+"\n\n"), data...)
	if err = fsutil.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("cannot update %s (%w), add this line at its top yourself:\n  %s", path, err, IncludeLine())
	}
	return nil
}

// RemoveInclude undoes EnsureInclude.
func RemoveInclude() error {
	path := userConfig()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read ssh config: %w", err)
	}
	if !HasInclude(data) {
		return nil
	}
	var kept []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if !isInclude(line) {
			kept = append(kept, line)
		}
	}
	out := strings.TrimLeft(strings.Join(kept, "\n"), "\n")
	return fsutil.WriteFile(path, []byte(out), 0o600)
}

// HasInclude reports whether an ssh config already includes nk's file.
func HasInclude(data []byte) bool {
	for line := range strings.SplitSeq(string(data), "\n") {
		if isInclude(line) {
			return true
		}
	}
	return false
}

func isInclude(line string) bool {
	return strings.ReplaceAll(strings.TrimSpace(line), `"`, "") ==
		strings.ReplaceAll(IncludeLine(), `"`, "")
}

// userConfig resolves ~/.ssh/config through symlinks, so dotfile managers
// keep their link and nk edits the real file.
func userConfig() string {
	path := paths.SSHUserConfig()
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}
