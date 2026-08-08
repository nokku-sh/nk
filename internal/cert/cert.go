// Package cert provides X.509 certificate utilities for the nk CLI:
// private key generation, PKCS#10 CSR creation, and PEM file output.
package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/util"
)

// GenerateKey creates a new private key of the given type.
// Accepts the same key type strings as the SSH identity key
// (ed25519, rsa-2048, rsa-4096, ecdsa-p256, ecdsa-p384, ecdsa-p521).
func GenerateKey(keyType string) (crypto.PrivateKey, error) {
	kt, ok := ssh.ParseKeyType(keyType)
	if !ok {
		return nil, fmt.Errorf(
			"invalid key type %q. Allowed choices are: %v",
			keyType,
			ssh.ValidKeyTypes,
		)
	}

	switch kt {
	case ssh.KeyTypeTPM:
		// X.509 issuance writes a private key file, which a TPM key can
		// never produce.
		return nil, fmt.Errorf(
			"key type %q is not supported for X.509 certificates; pass --key-type (e.g. ed25519)",
			keyType,
		)
	case ssh.KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case ssh.KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case ssh.KeyTypeECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ssh.KeyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case ssh.KeyTypeECDSAP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case ssh.KeyTypeEd25519:
		fallthrough
	default:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
}

// NewCSR builds a PEM-encoded PKCS#10 certificate signing request with
// the given common name and subject alternative names.
//
// SANs accept typed prefixes (dns:, ip:, email:, uri:) or bare values,
// which are auto-detected: parseable IPs become IP SANs, values
// containing "://" become URI SANs, values containing "@" become email
// SANs, and everything else becomes a DNS SAN.
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
