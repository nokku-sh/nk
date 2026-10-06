package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
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
func WriteConfigs(s *state.State) error {
	if err := fsutil.WriteIfChanged(paths.SSHConfigFile(), renderSSHConfig(s, nkCommand()), 0o600); err != nil {
		return err
	}
	if err := fsutil.WriteIfChanged(paths.KnownHostsFile(), renderKnownHosts(s), 0o600); err != nil {
		return err
	}
	return ensureInclude()
}

func renderSSHConfig(s *state.State, nk string) []byte {
	nameCount := make(map[string]int)
	for _, t := range s.Targets {
		if usable(t) {
			nameCount[t.Name]++
		}
	}

	var b bytes.Buffer
	b.WriteString(header)
	for _, t := range s.Targets {
		if !usable(t) {
			continue
		}
		host := t.Name
		if nameCount[t.Name] > 1 {
			ws := s.WorkspaceName(t.WorkspaceID)
			if !safeToken(ws) {
				ws = t.WorkspaceID
			}
			host = ws + "/" + t.Name
		}

		// ssh loads CertificateFile before it starts the ProxyCommand, so the
		// Match exec renews the certificate first. The private key lives in
		// the TPM or the wrapped signer state, so IdentityFile is the public
		// half and the agent signs. Only the first account is the default,
		// others work with ssh <user>@<host>. The proxy gets the target id,
		// since ssh lowercases %h.
		fmt.Fprintf(&b, `Match originalhost %s exec %s

Host %s
    User %s
    ProxyCommand %s proxy %s %%p
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

`, host, configValue(nk+" prepare "+t.ID), host, t.Usernames[0], nk, t.ID, t.ID,
			configValue(paths.SSHCertificate(t.ID)), configValue(paths.PubKeyFile()),
			configValue(paths.AgentSocket()), configValue(paths.KnownHostsFile()))
	}
	return b.Bytes()
}

// renderKnownHosts scopes trust to the target id, which is the HostKeyAlias
// in ssh_config, never a global "*".
func renderKnownHosts(s *state.State) []byte {
	var b bytes.Buffer
	b.WriteString(header)
	for _, t := range s.Targets {
		if t.Manual() {
			// A manual host presents its own key, not a CA-signed one.
			if key := strings.TrimSpace(t.HostPublicKey); safeLine(key) {
				fmt.Fprintf(&b, "%s %s\n", t.ID, key)
			}
			continue
		}
		ca := s.CAByID(t.CAID)
		if ca == nil {
			continue
		}
		// A daemon that missed a rollover still shows a host certificate
		// from the replaced key.
		for _, key := range ca.TrustedKeys() {
			if safeLine(key) {
				fmt.Fprintf(&b, "@cert-authority %s %s\n", t.ID, key)
			}
		}
	}
	return b.Bytes()
}

// nkCommand names this nk by an absolute path, so ssh started without nk on
// its PATH (IDEs, cron, git GUIs) still finds it and no other nk runs. The
// PATH entry is preferred when it is this binary, since package managers keep
// that path stable across upgrades.
func nkCommand() string {
	self, err := os.Executable()
	if err != nil {
		return "nk"
	}
	bin := self
	if found, lookErr := exec.LookPath("nk"); lookErr == nil && filepath.IsAbs(found) && sameFile(found, self) {
		bin = found
	}
	// ssh expands % tokens and hands the line to a shell, so anything a
	// quoted path cannot carry falls back to a PATH lookup.
	if strings.ContainsAny(bin, "\"$`%\\\n") {
		return "nk"
	}
	if strings.ContainsAny(bin, " \t") {
		return `"` + bin + `"`
	}
	return bin
}

func sameFile(a, b string) bool {
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
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

// configValue quotes a value for ssh_config. Quotes cover spaces, and ssh
// unescapes \\ and \", which Windows paths, pipes, and quoted commands need.
func configValue(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// includeLine is the line nk puts on top of ~/.ssh/config.
func includeLine() string {
	return "Include " + configValue(paths.SSHConfigFile())
}

// ensureInclude prepends includeLine to ~/.ssh/config when it is missing. It
// goes on top because an Include after a Host line would be scoped to it.
func ensureInclude() error {
	path := userConfig()
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read ssh config: %w", err)
	}
	if HasInclude(data) {
		return nil
	}
	out := append([]byte(includeLine()+"\n\n"), data...)
	if err = fsutil.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("cannot update %s (%w), add this line at its top yourself:\n  %s", path, err, includeLine())
	}
	return nil
}

// RemoveInclude undoes ensureInclude.
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
		strings.ReplaceAll(includeLine(), `"`, "")
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
