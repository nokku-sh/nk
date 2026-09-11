package manual

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// PrincipalsListCommand lists the principal files that already exist on the host.
const PrincipalsListCommand = `for f in ` + PrincipalsDir + `/*; do
  if [ -f "$f" ]; then basename "$f"; fi
done`

// reloadMarker is echoed by the write script when sshd picked up the new
// configuration.
const reloadMarker = "reloaded sshd"

// File is one file a manual sync writes on the target host.
type File struct {
	Path    string
	Mode    os.FileMode
	Content []byte
}

// Reloaded reports whether the write script confirmed an sshd reload.
func Reloaded(out string) bool {
	return strings.Contains(out, reloadMarker)
}

// HostFiles renders the host files for one sync: the trusted CA key, the sshd
// drop-in, and a principal file per local account. An account with no grants
// still gets an empty file, so a revoked grant denies by default.
func HostFiles(caKey string, grants map[string][]string, local []string) []File {
	files := []File{
		{Path: CAPath, Mode: CAFileMode, Content: []byte(strings.TrimSpace(caKey) + "\n")},
		{Path: DropInPath, Mode: DropInFileMode, Content: RenderDropIn(CAPath, PrincipalsDir)},
	}
	for _, name := range local {
		files = append(files, File{
			Path:    PrincipalsDir + "/" + name,
			Mode:    PrincipalsFileMode,
			Content: RenderPrincipalFile(grants[name]),
		})
	}
	return files
}

// StalePrincipals lists principal files whose account the host no longer has,
// so an allowlist never outlives its account.
func StalePrincipals(existing, local []string) (stale []string) {
	for _, name := range existing {
		if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
			continue
		}
		if !slices.Contains(local, name) {
			stale = append(stale, PrincipalsDir+"/"+name)
		}
	}
	return stale
}

// WriteScript writes changed files, removes the principal files of vanished
// accounts, validates sshd, and reloads it. Every action reports on stdout.
func WriteScript(files []File, stale []string) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	fmt.Fprintf(&b, "mkdir -p %s\n", shellQuote(PrincipalsDir))
	fmt.Fprintf(&b, "chmod %04o %s\n", PrincipalsDirMode, shellQuote(PrincipalsDir))
	fmt.Fprintf(&b, "mkdir -p %s\n", shellQuote(DropInDir))

	for _, f := range files {
		quotedPath := shellQuote(f.Path)
		quoted := shellQuote(string(f.Content))
		fmt.Fprintf(&b, "if [ -f %s ] && printf '%%s' %s | cmp -s - %s; then\n",
			quotedPath, quoted, quotedPath)
		fmt.Fprintf(&b, "  printf '%%-9s %%s\\n' unchanged %s\n", quotedPath)
		b.WriteString("else\n")
		// Stage then rename, so a torn write can never be the file sshd loads.
		fmt.Fprintf(&b, "  printf '%%s' %s > %s\n", quoted, shellQuote(f.Path+".nokku-tmp"))
		fmt.Fprintf(&b, "  chmod %04o %s\n", f.Mode, shellQuote(f.Path+".nokku-tmp"))
		fmt.Fprintf(&b, "  mv -f %s %s\n", shellQuote(f.Path+".nokku-tmp"), quotedPath)
		fmt.Fprintf(&b, "  printf '%%-9s %%s\\n' written %s\n", quotedPath)
		b.WriteString("fi\n")
	}

	for _, path := range stale {
		fmt.Fprintf(&b, "rm -f %s\n", shellQuote(path))
		fmt.Fprintf(&b, "printf '%%-9s %%s\\n' removed %s\n", shellQuote(path))
	}

	b.WriteString("sshd -t\n")
	// The unit is sshd on RHEL and ssh on Debian. A host without systemd is
	// reloaded by hand, which the caller reports.
	b.WriteString("if systemctl reload sshd 2>/dev/null; then\n")
	fmt.Fprintf(&b, "  echo %s\n", shellQuote(reloadMarker))
	b.WriteString("elif systemctl reload ssh 2>/dev/null; then\n")
	fmt.Fprintf(&b, "  echo %s\n", shellQuote(reloadMarker))
	b.WriteString("fi\n")
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
