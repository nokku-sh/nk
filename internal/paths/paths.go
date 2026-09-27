// Package paths resolves where nk keeps its files.
package paths

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// EnsurePaths creates the state directories and stops the command early when
// the account has no home directory.
func EnsurePaths() error {
	if _, err := os.UserHomeDir(); err != nil {
		return fmt.Errorf("cannot resolve the home directory: %w", err)
	}
	for _, dir := range []string{ConfigPath(), SSHCertPath()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("cannot create directory %s: %w", dir, err)
		}
	}
	return nil
}

// ConfigPath is ~/.config/nk on every OS. The OS config dir on macOS has a
// space in it, which every generated ssh_config line would have to survive.
func ConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "nk")
}

// SSHUserConfig is the user's own ~/.ssh/config.
func SSHUserConfig() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

func ConfigFile() string      { return filepath.Join(ConfigPath(), "config.json") }
func CacheFile() string       { return filepath.Join(ConfigPath(), "cache.json") }
func SSHConfigFile() string   { return filepath.Join(ConfigPath(), "ssh_config") }
func KnownHostsPath() string  { return filepath.Join(ConfigPath(), "known_hosts") }
func PubKeyFile() string      { return filepath.Join(ConfigPath(), "nokku.pub") }
func SSHCertPath() string     { return filepath.Join(ConfigPath(), "certs") }
func SignerStateFile() string { return filepath.Join(ConfigPath(), "signer.json") }
func SSHSignerFile() string   { return filepath.Join(ConfigPath(), "ssh-signer.json") }

// AgentSocket is a unix socket, or a per-user named pipe on Windows, where
// OpenSSH only speaks to agents over pipes.
func AgentSocket() string {
	if runtime.GOOS == "windows" {
		sum := sha256.Sum256([]byte(ConfigPath()))
		return `\\.\pipe\nk-agent-` + hex.EncodeToString(sum[:6])
	}
	return filepath.Join(ConfigPath(), "agent.sock")
}

// SSHCertificate is the signed SSH certificate for caID. IDs are UUIDs,
// checked when the backend snapshot is mapped.
func SSHCertificate(caID string) string {
	return filepath.Join(SSHCertPath(), caID+"-cert.pub")
}

// SSHCertificates returns all locally cached SSH certificate paths.
func SSHCertificates() ([]string, error) {
	return filepath.Glob(filepath.Join(SSHCertPath(), "*-cert.pub"))
}

// RemoveConfigDir removes the local config directory, never ~/.ssh.
func RemoveConfigDir() error {
	if err := os.RemoveAll(ConfigPath()); err != nil {
		return fmt.Errorf("remove config dir: %w", err)
	}
	return nil
}
