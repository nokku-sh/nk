package util

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
)

const (
	ConfigDirname  = "nk"
	ConfigFilename = "config.json"
	CacheFilename  = "cache.json"
	KeyName        = "nokku"
)

func VerifyPaths() error {
	sshPath, err := SSHPath()
	if err != nil {
		return err
	}
	for _, dir := range []string{ConfigPath(), sshPath, SSHCertPath()} {
		if err = os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("cannot create directory %s: %w", dir, err)
		}
	}
	return nil
}

// EnsureSSHConfigInclude writes the Include directive into the user's
// ~/.ssh/config when it is missing. Called after a successful login.
func EnsureSSHConfigInclude() error {
	sshPath, err := SSHPath()
	if err != nil {
		return err
	}
	path := filepath.Join(sshPath, "config")
	include := fmt.Sprintf("Include %s", SSHConfigFile())

	// Read the existing config file (if it exists)
	var content []byte
	if _, err = os.Stat(path); err == nil {
		content, err = os.ReadFile(filepath.Clean(path))
		if err != nil {
			return fmt.Errorf("failed to read ssh config: %w", err)
		}
	}

	if strings.Contains(string(content), include) {
		return nil
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s\n\n", include)
	buf.Write(content)
	return WriteFile(path, buf.Bytes(), 0o600)
}

// Common Paths ---------------------------------------------------------------

func ConfigPath() string {
	return filepath.Join(xdg.ConfigHome, ConfigDirname)
}

// SSHCertPath returns the directory holding the signed SSH certificates.
func SSHCertPath() string {
	return filepath.Join(ConfigPath(), "certs")
}

func KnownHostsPath() string {
	return filepath.Join(ConfigPath(), "known_hosts")
}

func SSHPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh"), nil
}

// File Paths -----------------------------------------------------------------

func ConfigFile() string {
	return filepath.Join(ConfigPath(), ConfigFilename)
}

func CacheFile() string {
	return filepath.Join(ConfigPath(), CacheFilename)
}

func KeyFile() string {
	return filepath.Join(ConfigPath(), KeyName)
}

func PubKeyFile() string {
	return filepath.Join(ConfigPath(), KeyName+".pub")
}

func AgentSocket() string {
	return filepath.Join(ConfigPath(), "agent.sock")
}

func SSHConfigFile() string {
	return filepath.Join(ConfigPath(), "ssh_config")
}

// SSHCertificate returns the path of the signed SSH certificate for caID.
func SSHCertificate(caID string) string {
	return filepath.Join(SSHCertPath(), caID+"-cert.pub")
}

// SSHCertificates returns all locally cached SSH certificate paths.
func SSHCertificates() ([]string, error) {
	return filepath.Glob(filepath.Join(SSHCertPath(), "*-cert.pub"))
}

// Helpers --------------------------------------------------------------------

// CleanupPaths removes safe application data, not ssh dir!
func CleanupPaths() {
	if err := os.RemoveAll(ConfigPath()); err != nil {
		slog.Warn("failed to remove config dir", "path", ConfigPath(), "err", err)
	}
}
