package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

// CertificateFresh reports whether the cached cert for caID is valid, signed by
// the CA's current key, and stays valid for at least margin longer. A cert
// inside the margin counts as stale so it is re-signed while the backend is
// still reachable.
func CertificateFresh(caID, caPublicKey string, margin time.Duration) bool {
	path, err := paths.SSHCertificate(caID)
	if err != nil {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caPublicKey))
	if err != nil {
		return false
	}
	if err = VerifyCertificateForCA(data, caPub); err != nil {
		return false
	}
	_, validBefore, err := CertificateValidity(data)
	if err != nil {
		return false
	}
	return time.Until(validBefore) > margin
}

// CertificateOnDisk reports whether a cached certificate file exists for caID,
// fresh or not. Used to fall back to the last cached certificate when signing
// fails.
func CertificateOnDisk(caID string) bool {
	path, err := paths.SSHCertificate(caID)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// VerifyCertificateForCA checks that data is a certificate valid now and that
// caPub signed it.
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

// VerifyCertificate checks that data is an SSH certificate valid at the current
// time.
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

// CertificateValidity parses a signed SSH certificate and returns its validity
// window.
func CertificateValidity(data []byte) (validAfter, validBefore time.Time, err error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return validAfter, validBefore, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return validAfter, validBefore, errors.New("invalid certificate format")
	}
	return unixTime(cert.ValidAfter), unixTime(cert.ValidBefore), nil
}

// unixTime converts an SSH certificate validity timestamp to a Go time,
// clamping uint64 overflow.
func unixTime(t uint64) time.Time {
	if t > math.MaxInt64 {
		return time.Unix(math.MaxInt64, 0)
	}
	return time.Unix(int64(t), 0)
}

// CleanupCerts removes certificate files for CA IDs no longer in the provided set.
func CleanupCerts(cas []state.CA) error {
	existingFiles, err := paths.SSHCertificates()
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

func removeCerts() error {
	certs, err := paths.SSHCertificates()
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
