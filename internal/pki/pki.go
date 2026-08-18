// Package pki provides X.509 (PKI) utilities for the nk CLI: private key
// generation, PKCS#10 CSR creation, CA matching, and PEM file output. It is
// strictly separate from the SSH certificate handling in internal/ssh.
package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/nokku-sh/nk/internal/util"
)

// GenerateKey creates a new ed25519 private key. X.509 issuance writes the
// private key to disk, so TPM-backed keys cannot be used here.
func GenerateKey() (crypto.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// NewCSR builds a PEM-encoded PKCS#10 CSR with the given common name
// and subject alternative names. SANs accept typed prefixes (dns:, ip:,
// email:, uri:) or bare values, which are auto-detected by content.
func NewCSR(priv crypto.PrivateKey, cn string, sans []string) (string, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	for _, san := range sans {
		if err := addSAN(tmpl, san); err != nil {
			return "", err
		}
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func addSAN(tmpl *x509.CertificateRequest, san string) error {
	if typ, val, found := strings.Cut(san, ":"); found {
		switch strings.ToLower(typ) {
		case "dns":
			tmpl.DNSNames = append(tmpl.DNSNames, val)
			return nil
		case "ip":
			ip := net.ParseIP(val)
			if ip == nil {
				return fmt.Errorf("invalid IP SAN %q", val)
			}
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			return nil
		case "email":
			tmpl.EmailAddresses = append(tmpl.EmailAddresses, val)
			return nil
		case "uri":
			u, err := url.Parse(val)
			if err != nil {
				return fmt.Errorf("invalid URI SAN %q: %w", val, err)
			}
			tmpl.URIs = append(tmpl.URIs, u)
			return nil
		}
	}

	if ip := net.ParseIP(san); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		return nil
	}
	if strings.Contains(san, "://") {
		u, err := url.Parse(san)
		if err != nil {
			return fmt.Errorf("invalid URI SAN %q: %w", san, err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
		return nil
	}
	if strings.Contains(san, "@") {
		tmpl.EmailAddresses = append(tmpl.EmailAddresses, san)
		return nil
	}
	tmpl.DNSNames = append(tmpl.DNSNames, san)
	return nil
}

// WriteKey writes a private key as PKCS#8 PEM with mode 0600.
func WriteKey(path string, priv crypto.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	return util.WriteFile(
		path,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		0o600,
	)
}

// WriteCert writes a PEM-encoded certificate with mode 0644.
func WriteCert(path string, certPEM []byte) error {
	return util.WriteFile(path, certPEM, 0o644)
}
