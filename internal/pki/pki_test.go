package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
)

func parseCSR(t *testing.T, csrPEM string) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("CSR is not valid PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if err = csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	return csr
}

func TestNewCSR(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, err := NewCSR(priv, "my-service", []string{
		"svc.internal", // bare DNS
		"10.0.0.1",     // bare IP
		"spiffe://nokku.local/ns/default/sa/test", // bare URI
		"admin@example.com",                       // bare email
		"dns:alt.internal",                        // typed DNS
		"ip:192.168.1.1",                          // typed IP
		"email:ops@example.com",                   // typed email
		"uri:https://api.internal/v1",             // typed URI
	})
	if err != nil {
		t.Fatalf("NewCSR failed: %v", err)
	}

	csr := parseCSR(t, csrPEM)

	if csr.Subject.CommonName != "my-service" {
		t.Errorf("unexpected CN: %s", csr.Subject.CommonName)
	}

	wantDNS := []string{"svc.internal", "alt.internal"}
	if len(csr.DNSNames) != len(wantDNS) {
		t.Fatalf("expected %d DNS SANs, got %v", len(wantDNS), csr.DNSNames)
	}
	for i, name := range wantDNS {
		if csr.DNSNames[i] != name {
			t.Errorf("DNS SAN %d = %q, want %q", i, csr.DNSNames[i], name)
		}
	}

	if len(csr.IPAddresses) != 2 {
		t.Fatalf("expected 2 IP SANs, got %v", csr.IPAddresses)
	}
	if !csr.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("unexpected IP SAN: %v", csr.IPAddresses[0])
	}
	if !csr.IPAddresses[1].Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("unexpected IP SAN: %v", csr.IPAddresses[1])
	}

	if len(csr.URIs) != 2 {
		t.Fatalf("expected 2 URI SANs, got %v", csr.URIs)
	}
	if csr.URIs[0].String() != "spiffe://nokku.local/ns/default/sa/test" {
		t.Errorf("unexpected URI SAN: %v", csr.URIs[0])
	}

	wantEmails := []string{"admin@example.com", "ops@example.com"}
	if len(csr.EmailAddresses) != len(wantEmails) {
		t.Fatalf("expected %d email SANs, got %v", len(wantEmails), csr.EmailAddresses)
	}
}

func TestNewCSRRejectsBadIP(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewCSR(priv, "svc", []string{"ip:not-an-ip"}); err == nil {
		t.Error("expected error for invalid typed IP SAN")
	}
}

func TestGenerateKey(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	// Key must be usable for CSR creation.
	if _, err = NewCSR(priv, "test", nil); err != nil {
		t.Errorf("NewCSR with generated key failed: %v", err)
	}
	if _, ok := priv.(ed25519.PrivateKey); !ok {
		t.Errorf("GenerateKey() = %T, want ed25519.PrivateKey", priv)
	}
}
