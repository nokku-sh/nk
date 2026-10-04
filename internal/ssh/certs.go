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

// ParseCert parses an SSH certificate in authorized_keys format.
func ParseCert(data []byte) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not an ssh certificate")
	}
	return cert, nil
}

// CertWindow returns when cert becomes valid and when it expires.
func CertWindow(cert *ssh.Certificate) (after, before time.Time) {
	return unixTime(cert.ValidAfter), unixTime(cert.ValidBefore)
}

// CheckCert verifies that data is a certificate signed by caKey that is valid
// now and stays valid for at least margin.
func CheckCert(data []byte, caKey string, margin time.Duration) error {
	cert, err := ParseCert(data)
	if err != nil {
		return err
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey))
	if err != nil {
		return fmt.Errorf("parse ca key: %w", err)
	}
	if cert.SignatureKey == nil || !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
		return errors.New("certificate signed by a different CA")
	}
	after, before := CertWindow(cert)
	if time.Now().Before(after) || time.Until(before) <= margin {
		return errors.New("certificate expired or not yet valid")
	}
	return nil
}

// CertValid reports whether the cached certificate for ca passes CheckCert.
func CertValid(ca state.CA, margin time.Duration) bool {
	data, err := os.ReadFile(paths.SSHCertificate(ca.ID))
	return err == nil && CheckCert(data, ca.PublicKey, margin) == nil
}

// CertFresh reports whether the cached certificate for ca is valid and still
// in the first half of its life. It is renewed from there on, so a backend
// outage finds an active user with at least half a lifetime left.
func CertFresh(ca state.CA) bool {
	data, err := os.ReadFile(paths.SSHCertificate(ca.ID))
	if err != nil {
		return false
	}
	cert, err := ParseCert(data)
	if err != nil {
		return false
	}
	after, before := CertWindow(cert)
	return CheckCert(data, ca.PublicKey, before.Sub(after)/2) == nil
}

func unixTime(t uint64) time.Time {
	return time.Unix(int64(min(t, math.MaxInt64)), 0)
}

// CleanupCerts removes certificate files for CAs not in keep.
func CleanupCerts(keep []state.CA) error {
	files, err := paths.SSHCertificates()
	if err != nil {
		return err
	}
	valid := make(map[string]bool, len(keep))
	for _, ca := range keep {
		valid[filepath.Base(paths.SSHCertificate(ca.ID))] = true
	}
	for _, f := range files {
		if valid[filepath.Base(f)] {
			continue
		}
		if err = os.Remove(f); err != nil {
			return fmt.Errorf("remove stale certificate: %w", err)
		}
	}
	return nil
}
