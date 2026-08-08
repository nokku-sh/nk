package ssh

import (
	"bytes"
	"fmt"
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
// on the same TPM reproduces the enrolled key.
//
// Without a TPM the behavior depends on the current state: if a TPM identity
// is already enrolled (public key without a private key file), silently
// downgrading would break authentication, so an error is returned; otherwise
// (e.g. CI/CD) it falls back to a default software key.
func setupTPMKey() error {
	key, err := tpm.OpenKey(sshTPMSalt)
	if err != nil {
		if TPMKeyActive() {
			return fmt.Errorf(
				"TPM identity is enrolled but the TPM is unavailable: %w; remove %s to start over",
				err,
				util.PubKeyFile(),
			)
		}
		fmt.Fprintf(
			os.Stderr,
			"warning: TPM unavailable (%v), using a %s key instead\n",
			err,
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
		// The identity changed (first enrollment, or the TPM was cleared or
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

// TPMKeyActive reports whether the enrolled SSH identity is TPM-backed: a
// public key exists on disk, but no private key file does.
func TPMKeyActive() bool {
	return util.FileExists(util.PubKeyFile()) && !util.FileExists(util.KeyFile())
}

// IdentityStatus describes the enrolled SSH identity for diagnostics.
func IdentityStatus() string {
	if TPMKeyActive() {
		return "TPM 2.0 (ecdsa-p256), private key never touches disk"
	}
	if util.FileExists(util.KeyFile()) {
		kt, err := detectKeyType(util.KeyFile())
		if err == nil {
			return fmt.Sprintf("software key (%s), stored in %s", kt, util.KeyFile())
		}
		return fmt.Sprintf("software key (unknown type), stored in %s", util.KeyFile())
	}
	return "none enrolled yet"
}
