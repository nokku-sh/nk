package paths

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nokku-sh/mon/fsutil"
)

const (
	ConfigDirname  = "nk"
	ConfigFilename = "config.json"
	CacheFilename  = "cache.json"
	KeyName        = "nokku"
)

func EnsurePaths() error {
	if _, err := os.UserConfigDir(); err != nil {
		return fmt.Errorf("cannot resolve the user config directory: %w", err)
	}
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

// EnsureSSHConfigInclude writes the Include directive into ~/.ssh/config if it is missing.
func EnsureSSHConfigInclude() error {
	sshPath, err := SSHPath()
	if err != nil {
		return err
	}
	path := filepath.Join(sshPath, "config")
	include := fmt.Sprintf("Include %s", SSHConfigFile())

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
	return fsutil.WriteFile(path, buf.Bytes(), 0o600)
}

// RemoveSSHConfigInclude removes the Include directive EnsureSSHConfigInclude added.
func RemoveSSHConfigInclude() error {
	sshPath, err := SSHPath()
	if err != nil {
		return err
	}
	path := filepath.Join(sshPath, "config")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to read ssh config: %w", err)
	}

	include := fmt.Sprintf("Include %s", SSHConfigFile())
	removed := false
	var kept []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.TrimSpace(line) == include {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return nil
	}

	// The prepend left a blank separator line above the user's content.
	for len(kept) > 0 && strings.TrimSpace(kept[0]) == "" {
		kept = kept[1:]
	}
	out := strings.Join(kept, "\n")
	if strings.TrimSpace(out) != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return fsutil.WriteIfChanged(path, []byte(out), 0o600)
}

// Common Paths ---------------------------------------------------------------

// ConfigPath resolves the directory holding nk's state. [os.UserConfigDir]
// fails only when the account has no home directory, and state must never land
// in a shared temp dir where another user could plant or read it, so the
// fallback stays per-user. EnsurePaths reports that case and stops every command
// before state is touched.
func ConfigPath() string {
	dir, err := os.UserConfigDir()
	if err == nil {
		return filepath.Join(dir, ConfigDirname)
	}
	home, homeErr := os.UserHomeDir()
	if homeErr != nil {
		return ConfigDirname
	}
	return filepath.Join(home, ".config", ConfigDirname)
}

// SSHCertPath returns the directory holding the signed SSH certificates.
func SSHCertPath() string {
	return filepath.Join(ConfigPath(), "certs")
}

// SignerStateFile returns the machine signing identity path. The file belongs
// to the shared mon/tpm package, so its JSON shape must not change.
func SignerStateFile() string {
	return filepath.Join(ConfigPath(), "signer.json")
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

// KeyFile is the legacy plaintext key path. legacy: only referenced to remove
// pre-Signer files.
func KeyFile() string {
	return filepath.Join(ConfigPath(), KeyName)
}

// SoftKeyFile is the pre-Signer software SSH key sealed to the machine
// fingerprint. legacy: only referenced to remove pre-Signer files.
func SoftKeyFile() string {
	return filepath.Join(ConfigPath(), KeyName+".key")
}

// SSHSignerFile returns the machine SSH identity path. The file belongs to the
// shared mon/tpm package, so its JSON shape must not change.
func SSHSignerFile() string {
	return filepath.Join(ConfigPath(), "ssh-signer.json")
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

// SSHCertificate returns the path of the signed SSH certificate for caID. The
// id comes from the backend, so it must be a plain path segment. Anything else
// is refused rather than cleaned into the config directory.
func SSHCertificate(caID string) (string, error) {
	if !validID(caID) {
		return "", fmt.Errorf("unsafe certificate authority id %q", caID)
	}
	return filepath.Join(SSHCertPath(), caID+"-cert.pub"), nil
}

// validID reports whether id is safe to use as a single path segment.
func validID(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	for _, r := range id {
		if r <= ' ' || r == 0x7f || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

// SSHCertificates returns all locally cached SSH certificate paths.
func SSHCertificates() ([]string, error) {
	return filepath.Glob(filepath.Join(SSHCertPath(), "*-cert.pub"))
}

// Helpers --------------------------------------------------------------------

// RemoveConfigDir removes the local config directory, never ~/.ssh.
func RemoveConfigDir() error {
	if err := os.RemoveAll(ConfigPath()); err != nil {
		return fmt.Errorf("remove config dir: %w", err)
	}
	return nil
}
