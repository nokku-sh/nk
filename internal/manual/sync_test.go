package manual

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostFiles(t *testing.T) {
	t.Parallel()

	files := HostFiles("ca-key\n", map[string][]string{"root": {"id-1"}}, []string{"alice", "root"})
	require.Len(t, files, 4, "the CA, the drop-in, and one file per local account")

	byPath := make(map[string]File, len(files))
	for _, f := range files {
		byPath[f.Path] = f
	}

	assert.Equal(t, "ca-key\n", string(byPath[CAPath].Content))
	assert.Equal(t, DropInPath, byPath[DropInPath].Path)
	assert.Equal(t, "id-1\n", string(byPath[PrincipalsDir+"/root"].Content))
	assert.Empty(t, byPath[PrincipalsDir+"/alice"].Content,
		"an account with no grants gets an empty deny-by-default file")
}

func TestStalePrincipals(t *testing.T) {
	t.Parallel()

	got := StalePrincipals([]string{"bob", "..", "a/b", "", "alice"}, []string{"alice"})
	assert.Equal(t, []string{PrincipalsDir + "/bob"}, got,
		"only real accounts that vanished become stale paths")
}

func TestReloaded(t *testing.T) {
	t.Parallel()

	assert.True(t, Reloaded("written /etc/ssh/nokku_ca.pub\nreloaded sshd\n"))
	assert.False(t, Reloaded("written /etc/ssh/nokku_ca.pub\n"))
}

func TestWriteScriptIsValidShell(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	files := HostFiles("ca-key\n", map[string][]string{"root": {"id-1"}}, []string{"weird'name"})
	script := WriteScript(files, []string{PrincipalsDir + "/gone"})

	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "generated script must parse: %s", out)
}
