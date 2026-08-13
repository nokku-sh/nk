package ssh

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/nokku-sh/nk/internal/util"
)

type KeyType string

const (
	KeyTypeEd25519   KeyType = "ed25519"
	KeyTypeRSA2048   KeyType = "rsa-2048"
	KeyTypeRSA4096   KeyType = "rsa-4096"
	KeyTypeECDSAP256 KeyType = "ecdsa-p256"
	KeyTypeECDSAP384 KeyType = "ecdsa-p384"
	KeyTypeECDSAP521 KeyType = "ecdsa-p521"
	// KeyTypeTPM keeps the private key inside a TPM 2.0 (ECDSA P-256).
	// Only the public key touches disk.
	KeyTypeTPM KeyType = "tpm"
)

func ParseKeyType(s string) (KeyType, bool) {
	kt := KeyType(strings.ToLower(s))
	switch kt {
	case KeyTypeEd25519,
		KeyTypeRSA2048,
		KeyTypeRSA4096,
		KeyTypeECDSAP256,
		KeyTypeECDSAP384,
		KeyTypeECDSAP521,
		KeyTypeTPM:
		return kt, true
	}
	return "", false
}

func DefaultKeyType() KeyType {
	return KeyTypeEd25519
}

var ValidKeyTypes = []KeyType{
	KeyTypeEd25519,
	KeyTypeRSA2048,
	KeyTypeRSA4096,
	KeyTypeECDSAP256,
	KeyTypeECDSAP384,
	KeyTypeECDSAP521,
	KeyTypeTPM,
}

// SetupKey ensures a keypair of the given type exists.
// If keys exist with a different type, they are replaced.
func SetupKey(keytype string) error {
	if keytype == "" {
		keytype = string(DefaultKeyType())
	}
	kt, ok := ParseKeyType(keytype)
	if !ok {
		return fmt.Errorf("invalid key type: %s", kt)
	}
	if kt == KeyTypeTPM {
		return setupTPMKey()
	}
	return setupFileKey(kt)
}

// setupFileKey ensures a software keypair of the given type exists.
// If keys exist with a different type, they are replaced.
func setupFileKey(kt KeyType) error {
	if util.FileExists(util.KeyFile()) && util.FileExists(util.PubKeyFile()) {
		existingType, err := detectKeyType(util.KeyFile())
		if err == nil && existingType == kt {
			return nil
		}
	}

	var pub crypto.PublicKey
	var priv crypto.PrivateKey
	var err error

	switch kt {
	case KeyTypeEd25519:
		pub, priv, err = generateEd25519()
	case KeyTypeRSA2048:
		pub, priv, err = generateRSA(2048)
	case KeyTypeRSA4096:
		pub, priv, err = generateRSA(4096)
	case KeyTypeECDSAP256:
		pub, priv, err = generateECDSA(elliptic.P256())
	case KeyTypeECDSAP384:
		pub, priv, err = generateECDSA(elliptic.P384())
	case KeyTypeECDSAP521:
		pub, priv, err = generateECDSA(elliptic.P521())
	case KeyTypeTPM:
		// TPM keys are handled by setupTPMKey, never as software keys.
		return fmt.Errorf("key type %s is not a software key", kt)
	default:
		return fmt.Errorf("unsupported key type: %s", kt)
	}
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

func generateEd25519() (crypto.PublicKey, crypto.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func generateRSA(bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return key.Public(), key, nil
}

func generateECDSA(curve elliptic.Curve) (crypto.PublicKey, crypto.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return key.Public(), key, nil
}

// detectKeyType reads a private key file and determines its type.
func detectKeyType(path string) (KeyType, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", err
	}

	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		// Check if the error is because the key is encrypted
		if errors.As(err, new(*ssh.PassphraseMissingError)) {
			fmt.Printf("Enter passphrase for %s: ", path)

			bytePassword, readErr := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println() // print a newline after pressing Enter
			if readErr != nil {
				return "", fmt.Errorf("failed to read passphrase: %w", readErr)
			}

			// Try parsing again with the provided passphrase
			key, err = ssh.ParseRawPrivateKeyWithPassphrase(data, bytePassword)
			if err != nil {
				return "", fmt.Errorf("incorrect passphrase or invalid key: %w", err)
			}
		} else {
			return "", err // It was a different error (e.g., malformed key)
		}
	}

	switch k := key.(type) {
	case *ed25519.PrivateKey:
		return KeyTypeEd25519, nil
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		switch bits {
		case 2048:
			return KeyTypeRSA2048, nil
		case 4096:
			return KeyTypeRSA4096, nil
		}
		return "", fmt.Errorf("unsupported RSA key size: %d", bits)
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return KeyTypeECDSAP256, nil
		case elliptic.P384():
			return KeyTypeECDSAP384, nil
		case elliptic.P521():
			return KeyTypeECDSAP521, nil
		}
		return "", fmt.Errorf("unsupported ECDSA curve")
	default:
		return "", fmt.Errorf("unknown key type: %T", key)
	}
}

func GetPubKey() (string, error) {
	pubKeyData, err := os.ReadFile(util.PubKeyFile())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(pubKeyData)), nil
}
