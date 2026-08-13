package ssh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adrg/xdg"

	"github.com/nokku-sh/nk/internal/util"
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
		if err := os.MkdirAll(filepath.Join(util.ConfigPath(), sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSetupKey(t *testing.T) {
	setupSSHDir(t)

	// First call should create keys
	if err := SetupKey("ed25519"); err != nil {
		t.Fatalf("SetupKey() error = %v", err)
	}

	if !util.FileExists(util.KeyFile()) {
		t.Error("private key not created")
	}
	if !util.FileExists(util.PubKeyFile()) {
		t.Error("public key not created")
	}

	// Second call should be a no-op (keys exist with same type)
	if err := SetupKey("ed25519"); err != nil {
		t.Fatalf("SetupKey() second call error = %v", err)
	}
}

func TestSetupKey_ReplaceWithDifferentType(t *testing.T) {
	setupSSHDir(t)

	// Create ed25519 key first
	if err := SetupKey("ed25519"); err != nil {
		t.Fatalf("SetupKey(ed25519) error = %v", err)
	}
	if !util.FileExists(util.KeyFile()) {
		t.Fatal("private key not created")
	}

	// Detect type
	kt, err := detectKeyType(util.KeyFile())
	if err != nil {
		t.Fatalf("detectKeyType() error = %v", err)
	}
	if kt != KeyTypeEd25519 {
		t.Fatalf("expected ed25519, got %s", kt)
	}

	// Replace with rsa-2048
	if err = SetupKey("rsa-2048"); err != nil {
		t.Fatalf("SetupKey(rsa-2048) error = %v", err)
	}

	// Detect new type
	kt, err = detectKeyType(util.KeyFile())
	if err != nil {
		t.Fatalf("detectKeyType() after replace error = %v", err)
	}
	if kt != KeyTypeRSA2048 {
		t.Fatalf("expected rsa-2048, got %s", kt)
	}
}

func TestSetupKey_AllTypes(t *testing.T) {
	types := []KeyType{
		KeyTypeEd25519,
		KeyTypeRSA2048,
		KeyTypeRSA4096,
		KeyTypeECDSAP256,
		KeyTypeECDSAP384,
		KeyTypeECDSAP521,
	}
	for _, kt := range types {
		t.Run(string(kt), func(t *testing.T) {
			setupSSHDir(t)

			if err := SetupKey(string(kt)); err != nil {
				t.Fatalf("SetupKey(%s) error = %v", kt, err)
			}
			if !util.FileExists(util.KeyFile()) {
				t.Error("private key not created")
			}
			if !util.FileExists(util.PubKeyFile()) {
				t.Error("public key not created")
			}

			detected, err := detectKeyType(util.KeyFile())
			if err != nil {
				t.Fatalf("detectKeyType() error = %v", err)
			}
			if detected != kt {
				t.Fatalf("detected %s, want %s", detected, kt)
			}

			_, err = GetPubKey()
			if err != nil {
				t.Fatalf("GetPubKey() error = %v", err)
			}
		})
	}
}

func TestGetPubKey(t *testing.T) {
	setupSSHDir(t)

	if err := SetupKey("ed25519"); err != nil {
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

func TestParseKeyType(t *testing.T) {
	tests := []struct {
		input string
		want  KeyType
		ok    bool
	}{
		{"ed25519", KeyTypeEd25519, true},
		{"Ed25519", KeyTypeEd25519, true},
		{"ED25519", KeyTypeEd25519, true},
		{"rsa-2048", KeyTypeRSA2048, true},
		{"rsa-4096", KeyTypeRSA4096, true},
		{"ecdsa-p256", KeyTypeECDSAP256, true},
		{"ecdsa-p384", KeyTypeECDSAP384, true},
		{"ecdsa-p521", KeyTypeECDSAP521, true},
		{"tpm", KeyTypeTPM, true},
		{"TPM", KeyTypeTPM, true},
		{"rsa-1024", "", false},
		{"dsa", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := ParseKeyType(tt.input)
		if ok != tt.ok {
			t.Errorf("ParseKeyType(%q) ok = %v, want %v", tt.input, ok, tt.ok)
		}
		if ok && got != tt.want {
			t.Errorf("ParseKeyType(%q) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestDefaultKeyType(t *testing.T) {
	if DefaultKeyType() != KeyTypeEd25519 {
		t.Errorf("DefaultKeyType() = %s, want ed25519", DefaultKeyType())
	}
}
