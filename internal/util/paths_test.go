package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathDerivation(t *testing.T) {
	configDir := ConfigPath()
	if !filepath.IsAbs(configDir) {
		t.Errorf("ConfigPath() = %q, expected absolute path", configDir)
	}
	if filepath.Base(configDir) != ConfigDirname {
		t.Errorf("ConfigPath() base = %q, want %q", filepath.Base(configDir), ConfigDirname)
	}

	for name, fn := range map[string]func() string{
		"ConfigFile":    ConfigFile,
		"CacheFile":     CacheFile,
		"KeyFile":       KeyFile,
		"PubKeyFile":    PubKeyFile,
		"SSHConfigFile": SSHConfigFile,
	} {
		t.Run(name, func(t *testing.T) {
			if got := fn(); filepath.Dir(got) != configDir {
				t.Errorf("%s() = %q, expected in %q", name, got, configDir)
			}
		})
	}

	t.Run("SSHCertPath", func(t *testing.T) {
		if got := SSHCertPath(); filepath.Dir(got) != configDir {
			t.Errorf("SSHCertPath() = %q, expected subdir of %q", got, configDir)
		}
		if got := KnownHostsPath(); filepath.Dir(got) != configDir {
			t.Errorf("KnownHostsPath() = %q, expected in %q", got, configDir)
		}
	})
}

func TestSSHPath(t *testing.T) {
	path, err := SSHPath()
	if err != nil {
		t.Fatalf("SSHPath() error = %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Errorf("SSHPath() = %q, expected absolute", path)
	}
	if filepath.Base(path) != ".ssh" {
		t.Errorf("SSHPath() base = %q, want .ssh", filepath.Base(path))
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(home, ".ssh") {
		t.Errorf("SSHPath() = %q, want %q", path, filepath.Join(home, ".ssh"))
	}
}

func TestCertificateFilenames(t *testing.T) {
	if got := filepath.Base(SSHCertificate("ca-test")); got != "ca-test-cert.pub" {
		t.Errorf("SSHCertificate() base = %q, want %q", got, "ca-test-cert.pub")
	}
	if got := filepath.Base(SSHCertificate("ca-123")); got != "ca-123-cert.pub" {
		t.Errorf("SSHCertificate() base = %q, want %q", got, "ca-123-cert.pub")
	}
}

func TestKnownHostsPathConsistency(t *testing.T) {
	p1 := KnownHostsPath()
	p2 := KnownHostsPath()
	if p1 != p2 {
		t.Errorf("KnownHostsPath() not idempotent: %q vs %q", p1, p2)
	}
}
