// Package manual renders the host-side files a daemonless target needs: the
// trusted user CA key, one principal file per local account, and the sshd
// drop-in that points sshd at both.
package manual

import (
	"slices"
	"strconv"
	"strings"
)

// Host layout shared with the daemon and the web UI.
const (
	CAPath        = "/etc/ssh/nokku_ca.pub"
	PrincipalsDir = "/etc/ssh/nokku_principals"
	DropInDir     = "/etc/ssh/sshd_config.d"
	DropInPath    = DropInDir + "/60-nokku.conf"

	// CAFileMode, PrincipalsFileMode, DropInFileMode, and PrincipalsDirMode
	// are the modes sshd requires for the host files.
	CAFileMode         = 0o644
	PrincipalsFileMode = 0o644
	DropInFileMode     = 0o644
	PrincipalsDirMode  = 0o755

	// maxLocalAccounts caps what one sync reports, so a pathological passwd
	// file cannot flood the backend.
	maxLocalAccounts = 100
)

// RenderPrincipalFile renders the subject UUIDs allowed to log in as one
// local account. An empty result denies certificate login for that account.
func RenderPrincipalFile(ids []string) []byte {
	sorted := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" {
			sorted = append(sorted, id)
		}
	}
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	if len(sorted) == 0 {
		return nil
	}
	return []byte(strings.Join(sorted, "\n") + "\n")
}

// RenderDropIn renders the sshd drop-in that trusts the Nokku CA and scopes
// certificate logins to the per-account principal files.
func RenderDropIn(caPath, principalsDir string) []byte {
	return []byte("TrustedUserCAKeys " + caPath + "\n" +
		"AuthorizedPrincipalsFile " + principalsDir + "/%u\n")
}

// LocalAccounts filters `getent passwd` output down to the accounts a human
// may log in as: uid 0 or at least 1000, and a real login shell.
func LocalAccounts(getent string) []string {
	var accounts []string
	for line := range strings.SplitSeq(getent, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		name := fields[0]
		if name == "" {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || (uid != 0 && uid < 1000) {
			continue
		}
		if noLoginShell(fields[6]) {
			continue
		}
		accounts = append(accounts, name)
	}

	slices.Sort(accounts)
	accounts = slices.Compact(accounts)
	if len(accounts) > maxLocalAccounts {
		accounts = accounts[:maxLocalAccounts]
	}
	return accounts
}

func noLoginShell(shell string) bool {
	return strings.HasSuffix(shell, "nologin") ||
		strings.HasSuffix(shell, "false") ||
		strings.HasSuffix(shell, "sync")
}

// RootLoginAllowed reports whether `sshd -T` output lets root log in with a
// certificate. Only public-key modes do. A dump without the option keeps
// sshd's default, which allows it.
func RootLoginAllowed(sshdConfig string) bool {
	for line := range strings.SplitSeq(sshdConfig, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || !strings.EqualFold(key, "permitrootlogin") {
			continue
		}
		switch strings.ToLower(value) {
		case "yes", "prohibit-password", "without-password":
			return true
		default:
			return false
		}
	}
	return true
}
