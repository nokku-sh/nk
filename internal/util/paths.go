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
	for _, dir := range []string{ConfigPath(), sshPath, CertPath()} {
		if err = os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("cannot create directory %s: %w", dir, err)
		}
	}
	return verifySSHConfig(sshPath)
}

// Common Paths ---------------------------------------------------------------

func ConfigPath() string {
	return filepath.Join(xdg.ConfigHome, ConfigDirname)
}

func CertPath() string {
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

func Certificate(caID string) string {
	return filepath.Join(CertPath(), caID+"-cert.pub")
}

func Certificates() ([]string, error) {
	return filepath.Glob(filepath.Join(CertPath(), "*-cert.pub"))
}

// Helpers --------------------------------------------------------------------

// verifySSHConfig checks if the user's ~/.ssh/config includes our app's config.
func verifySSHConfig(sshPath string) error {
	path := filepath.Join(sshPath, "config")
	include := fmt.Sprintf("Include %s", SSHConfigFile())

	// Read the existing config file (if it exists)
	var content []byte
	if _, err := os.Stat(path); err == nil {
		content, err = os.ReadFile(filepath.Clean(path))
		if err != nil {
			return fmt.Errorf("failed to read ssh config: %w", err)
		}
	}

	// Check if our directive is already there
	if strings.Contains(string(content), include) {
		return nil
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s\n\n", include)
	buf.Write(content)
	return WriteFile(path, buf.Bytes(), 0o600)
}

// CleanupPaths removes safe application data, not ssh dir!
func CleanupPaths() {
	if err := os.RemoveAll(ConfigPath()); err != nil {
		slog.Warn("failed to remove config dir", "path", ConfigPath(), "err", err)
	}
}
