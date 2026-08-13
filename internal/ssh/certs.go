package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/util"
)

// VerifyCertificateByID reports whether the cached cert for caID is
// present, valid, and signed by the CA's current key. Certs from a
// retired CA key must be re-signed even while valid.
func VerifyCertificateByID(caID, caPublicKey string) error {
	data, err := os.ReadFile(util.Certificate(caID))
	if err != nil {
		return err
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caPublicKey))
	if err != nil {
		return fmt.Errorf("parse CA public key: %w", err)
	}
	return VerifyCertificateForCA(data, caPub)
}

// VerifyCertificateForCA validates data's validity window and that it was
// signed by caPub.
func VerifyCertificateForCA(data []byte, caPub ssh.PublicKey) error {
	if err := VerifyCertificate(data); err != nil {
		return err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return errors.New("invalid certificate format")
	}
	if cert.SignatureKey == nil || !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
		return errors.New("certificate signed by a different CA")
	}
	return nil
}

// CertificateValidity parses a signed SSH certificate and returns its
// validity window.
func CertificateValidity(data []byte) (validAfter, validBefore time.Time, err error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return validAfter, validBefore, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return validAfter, validBefore, errors.New("invalid certificate format")
	}
	return util.Uint64ToUnixTime(cert.ValidAfter), util.Uint64ToUnixTime(cert.ValidBefore), nil
}

func VerifyCertificate(data []byte) error {
	validAfter, validBefore, err := CertificateValidity(data)
	if err != nil {
		return err
	}
	now := time.Now()
	if now.Before(validAfter) || now.After(validBefore) {
		return errors.New("certificate expired or not yet valid")
	}
	return nil
}

// CleanupCerts removes certificate files for CA IDs no longer in the provided set.
func CleanupCerts(cas []state.CA) error {
	existingFiles, err := util.Certificates()
	if err != nil {
		return fmt.Errorf("failed to get local certificates: %w", err)
	}

	validFiles := make(map[string]struct{})
	for _, ca := range cas {
		fileName := fmt.Sprintf("%s-cert.pub", ca.ID)
		validFiles[fileName] = struct{}{}
	}

	for _, filePath := range existingFiles {
		baseName := filepath.Base(filePath)

		if _, keep := validFiles[baseName]; !keep {
			if err = os.Remove(filePath); err != nil {
				return fmt.Errorf("failed to remove stale certificate %s: %w", filePath, err)
			}
		}
	}

	return nil
}

// removeCerts deletes all locally cached SSH certificates, forcing the CA to
// re-sign them for the current key.
func removeCerts() error {
	certs, err := util.Certificates()
	if err != nil {
		return fmt.Errorf("failed to get local certificates: %w", err)
	}
	for _, c := range certs {
		if err = os.Remove(c); err != nil {
			return fmt.Errorf("failed to remove certificate %s: %w", c, err)
		}
	}
	return nil
}
