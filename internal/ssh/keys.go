package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/nokku-sh/mon/fsutil"
	"github.com/nokku-sh/mon/tpm"

	"github.com/nokku-sh/nk/internal/paths"
)

const unknownHost = "unknown"

// sshSalt namespaces the SSH identity. It must differ from the DPoP salt,
// since two purposes sharing a salt on one machine share one identity.
var sshSalt = []byte("nokku-cli-ssh")

// newSSHSigner loads or creates the machine's SSH identity: TPM-resident when
// a TPM is usable, otherwise a software key wrapped to this machine.
func newSSHSigner(requireTPM bool) (tpm.Signer, error) {
	return tpm.NewSigner(tpm.SignerOptions{
		Salt:             sshSalt,
		StatePath:        paths.SSHSignerFile(),
		RequireTPM:       requireTPM,
		OnIdentityChange: tpm.RecreateIdentity,
	})
}

// SetupKey ensures the SSH identity exists and its authorized_keys line is on
// disk. A changed identity invalidates the cached certificates.
func SetupKey(requireTPM bool) error {
	signer, err := newSSHSigner(requireTPM)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()

	pub, err := cryptossh.NewPublicKey(signer.Public())
	if err != nil {
		return err
	}
	pubData := authorizedKeyLine(pub)

	old, readErr := os.ReadFile(paths.PubKeyFile())
	if readErr == nil && bytes.Equal(bytes.TrimSpace(old), bytes.TrimSpace(pubData)) {
		return removeLegacyKeys()
	}
	if err = fsutil.WriteFile(paths.PubKeyFile(), pubData, 0o600); err != nil {
		return err
	}
	if readErr == nil {
		// The identity changed, certificates for the old key are useless.
		slog.Warn("ssh identity changed, run nk login to register the new key")
		if err = removeCerts(); err != nil {
			return err
		}
	}
	return removeLegacyKeys()
}

// authorizedKeyLine renders the authorized_keys line for pub, with the
// hostname as the comment so an operator can tell where the entry came from.
func authorizedKeyLine(pub cryptossh.PublicKey) []byte {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = unknownHost
	}
	line := bytes.TrimSpace(cryptossh.MarshalAuthorizedKey(pub))
	return append(line, []byte(" "+hostname+"@nokku\n")...)
}

// removeLegacyKeys drops the pre-Signer key files. The signer cannot load
// them, so they are dead weight.
func removeLegacyKeys() error {
	for _, path := range []string{paths.SoftKeyFile(), paths.KeyFile()} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove legacy ssh key %s: %w", path, err)
		}
	}
	return nil
}

func GetPubKey() (string, error) {
	pubKeyData, err := os.ReadFile(paths.PubKeyFile())
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(pubKeyData)), nil
}

// IdentityMethod reports the active SSH identity method, "" when none exists.
func IdentityMethod() string { return tpm.IdentityMethod(paths.SSHSignerFile()) }

// IdentityStatus describes the active SSH identity for diagnostics.
func IdentityStatus() string {
	switch IdentityMethod() {
	case tpm.MethodTPM:
		return "TPM 2.0 (ecdsa-p256), private key never touches disk"
	case tpm.MethodSoft:
		return "software key (ecdsa-p256), machine-wrapped, served via the agent"
	default:
		return "not logged in yet"
	}
}
