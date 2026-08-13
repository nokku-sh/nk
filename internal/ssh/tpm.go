package ssh

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nk/internal/tpm"
	"github.com/nokku-sh/nk/internal/util"
)

// sshTPMSalt namespaces the SSH identity key derivation. It must stay
// distinct from the request-signing salts so each purpose derives its
// own key from the same TPM.
var sshTPMSalt = []byte("nokku-ssh")

// setupTPMKey maintains a TPM-resident SSH identity: only the public
// key is written to disk, the private key never leaves the TPM. The
// key is deterministic, so re-running reproduces the same key.
//
// Without a TPM it falls back to a software key, or errors when a TPM
// identity is already active (silently downgrading would break auth).
func setupTPMKey() error {
	key, err := tpm.OpenKey(sshTPMSalt)
	if err != nil {
		if TPMKeyActive() {
			return fmt.Errorf(
				"TPM identity exists but the TPM is unavailable: %w; remove %s to start over",
				err,
				util.PubKeyFile(),
			)
		}
		slog.Warn(
			"TPM unavailable, falling back to a software key",
			"err",
			err,
			"key_type",
			DefaultKeyType(),
		)
		return setupFileKey(DefaultKeyType())
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

	if old, readErr := os.ReadFile(util.PubKeyFile()); readErr != nil ||
		!bytes.Equal(bytes.TrimSpace(old), bytes.TrimSpace(pubData)) {
		if err = util.WriteFile(util.PubKeyFile(), pubData, 0o600); err != nil {
			return err
		}
		// The identity changed, so certs issued for the old key must
		// be re-signed for the new one.
		if err = removeCerts(); err != nil {
			return err
		}
	}

	// Don't leave a stale software key behind.
	if util.FileExists(util.KeyFile()) {
		return os.Remove(util.KeyFile())
	}
	return nil
}

// TPMKeyActive reports whether the active SSH identity is TPM-backed: a
// public key exists on disk, but no private key file does.
func TPMKeyActive() bool {
	return util.FileExists(util.PubKeyFile()) && !util.FileExists(util.KeyFile())
}

// IdentityStatus describes the active SSH identity for diagnostics.
func IdentityStatus() string {
	if TPMKeyActive() {
		return "TPM 2.0 (ecdsa-p256), private key never touches disk"
	}
	if util.FileExists(util.KeyFile()) {
		kt, err := detectKeyType(util.KeyFile())
		if err == nil {
			return fmt.Sprintf("software key (%s)", kt)
		}
		return "software key (unknown type)"
	}
	return "not logged in yet"
}
