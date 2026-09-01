package ssh

import (
	"bytes"
	"fmt"
	"os"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nk/internal/fsutil"
	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/tpm"
)

// sshTPMSalt namespaces the SSH identity key derivation. It must stay
// distinct from the request-signing salts so each purpose derives its
// own key from the same TPM.
var sshTPMSalt = []byte("nokku-ssh")

// setupTPMKey maintains a TPM-resident SSH identity: only the public
// key is written to disk, the private key never leaves the TPM. The
// key is deterministic, so re-running reproduces the same key.
func setupTPMKey() error {
	key, err := tpm.OpenKey(sshTPMSalt)
	if err != nil {
		return fmt.Errorf("open TPM key: %w", err)
	}
	defer func() { _ = key.Close() }()

	sshPub, err := cryptossh.NewPublicKey(key.Public())
	if err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	comment := fmt.Sprintf("%s@nokku", hostname)
	pubData := bytes.TrimSpace(cryptossh.MarshalAuthorizedKey(sshPub))
	pubData = append(pubData, []byte(" "+comment+"\n")...)

	if old, readErr := os.ReadFile(paths.PubKeyFile()); readErr != nil ||
		!bytes.Equal(bytes.TrimSpace(old), bytes.TrimSpace(pubData)) {
		if err = fsutil.WriteFile(paths.PubKeyFile(), pubData, 0o600); err != nil {
			return err
		}
		// The identity changed, so certs issued for the old key must
		// be re-signed for the new one.
		if err = removeCerts(); err != nil {
			return err
		}
	}

	// Don't leave a stale software key behind.
	if fsutil.FileExists(paths.KeyFile()) {
		return os.Remove(paths.KeyFile())
	}
	return nil
}

// TPMKeyActive reports whether the active SSH identity is TPM-backed: a
// public key exists on disk, but no private key file does.
func TPMKeyActive() bool {
	return fsutil.FileExists(paths.PubKeyFile()) && !fsutil.FileExists(paths.KeyFile())
}

// IdentityStatus describes the active SSH identity for diagnostics.
func IdentityStatus() string {
	if TPMKeyActive() {
		return "TPM 2.0 (ecdsa-p256), private key never touches disk"
	}
	if fsutil.FileExists(paths.KeyFile()) {
		return "software key (ed25519)"
	}
	return "not logged in yet"
}
