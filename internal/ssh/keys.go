package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nk/internal/util"
)

// SetupKey ensures the SSH identity exists: a TPM-resident key when a TPM is
// available, otherwise a software ed25519 key. requireTPM makes a missing TPM
// an error. A TPM identity is never silently downgraded to a software key.
func SetupKey(requireTPM bool) error {
	err := setupTPMKey()
	if err == nil {
		return nil
	}
	if TPMKeyActive() {
		return fmt.Errorf(
			"TPM identity exists but the TPM is unavailable: %w; remove %s to start over",
			err,
			util.PubKeyFile(),
		)
	}
	if requireTPM {
		return fmt.Errorf("require-tpm is set but no TPM key could be created: %w", err)
	}
	slog.Warn("TPM unavailable, falling back to a software key", "err", err)
	return setupFileKey()
}

// setupFileKey ensures a software ed25519 keypair exists.
func setupFileKey() error {
	if util.FileExists(util.KeyFile()) && util.FileExists(util.PubKeyFile()) {
		return nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	comment := fmt.Sprintf("%s@nokku", hostname)

	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return err
	}
	if err = util.WriteFile(util.KeyFile(), pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	pubData := ssh.MarshalAuthorizedKey(sshPub)
	pubData = bytes.TrimSpace(pubData)
	pubData = append(pubData, []byte(" "+comment+"\n")...)

	return util.WriteFile(util.PubKeyFile(), pubData, 0o600)
}

func GetPubKey() (string, error) {
	pubKeyData, err := os.ReadFile(util.PubKeyFile())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(pubKeyData)), nil
}
