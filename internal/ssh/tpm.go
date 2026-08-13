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

// sshTPMSalt namespaces the TPM key derivation for the SSH identity key. It
// must stay different from the request-signing salts ("nokku-cli",
// "nokku-daemon") so each purpose derives a distinct key from the same TPM.
var sshTPMSalt = []byte("nokku-ssh")

// setupTPMKey maintains a TPM-resident SSH identity: only the public key is
// written to PubKeyFile in authorized_keys format, the private key never
// leaves the TPM. The key is a deterministic primary key, so re-running this
// on the same TPM reproduces the same key.
//
// Without a TPM the behavior depends on the current state. If a TPM identity
// is already active (public key without a private key file), silently
// downgrading would break authentication, so an error is returned. Otherwise
// (e.g. CI/CD) it falls back to a software key.
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
		// The identity changed (first login, or the TPM was cleared or
		// replaced): certificates were issued for the previous key and must
		// be re-signed for the new one.
		if err = removeCerts(); err != nil {
			return err
		}
	}

	// A software key replaced by the TPM identity must not linger on disk.
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
