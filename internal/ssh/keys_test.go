package ssh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adrg/xdg"

	"github.com/nokku-sh/nk/internal/fsutil"
	"github.com/nokku-sh/nk/internal/paths"
)

// setTestConfigDir redirects the app's config dir into a fresh temp dir.
// xdg paths resolve at init, so the exported var is swapped instead
// (nolint:reassign // test isolation).
func setTestConfigDir(t *testing.T) {
	t.Helper()
	old := xdg.ConfigHome
	xdg.ConfigHome = t.TempDir()               //nolint:reassign // test isolation
	t.Cleanup(func() { xdg.ConfigHome = old }) //nolint:reassign // test isolation
}

func setupSSHDir(t *testing.T) {
	t.Helper()
	setTestConfigDir(t)
	for _, sub := range []string{"", "certs"} {
		if err := os.MkdirAll(filepath.Join(paths.ConfigPath(), sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSetupKey exercises the entry point: it must produce a public key
// regardless of whether a TPM is present (the software key is the fallback).
func TestSetupKey(t *testing.T) {
	setupSSHDir(t)

	if err := SetupKey(false); err != nil {
		t.Fatalf("SetupKey() error = %v", err)
	}
	if !fsutil.FileExists(paths.PubKeyFile()) {
		t.Error("public key not created")
	}
}

func TestSetupFileKey(t *testing.T) {
	setupSSHDir(t)

	// First call creates the keypair.
	if err := setupFileKey(); err != nil {
		t.Fatalf("setupFileKey() error = %v", err)
	}
	if !fsutil.FileExists(paths.KeyFile()) {
		t.Error("private key not created")
	}
	if !fsutil.FileExists(paths.PubKeyFile()) {
		t.Error("public key not created")
	}

	// Second call is a no-op.
	if err := setupFileKey(); err != nil {
		t.Fatalf("setupFileKey() second call error = %v", err)
	}
}

func TestGetPubKey(t *testing.T) {
	setupSSHDir(t)

	if err := setupFileKey(); err != nil {
		t.Fatal(err)
	}

	key, err := GetPubKey()
	if err != nil {
		t.Fatalf("GetPubKey() error = %v", err)
	}
	if key == "" {
		t.Error("GetPubKey() returned empty")
	}
}
