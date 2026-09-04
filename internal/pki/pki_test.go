package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseCSR(t *testing.T, csrPEM string) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block, "CSR is not valid PEM")
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature(), "CSR signature invalid")
	return csr
}

func TestNewCSR(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

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
	require.NoError(t, err)

	csr := parseCSR(t, csrPEM)

	assert.Equal(t, "my-service", csr.Subject.CommonName)
	assert.Equal(t, []string{"svc.internal", "alt.internal"}, csr.DNSNames)
	require.Len(t, csr.IPAddresses, 2)
	assert.True(t, csr.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")), "unexpected IP SAN: %v", csr.IPAddresses[0])
	assert.True(t, csr.IPAddresses[1].Equal(net.ParseIP("192.168.1.1")), "unexpected IP SAN: %v", csr.IPAddresses[1])
	assert.Equal(t, "spiffe://nokku.local/ns/default/sa/test", csr.URIs[0].String())
	assert.Len(t, csr.URIs, 2)
	assert.Equal(t, []string{"admin@example.com", "ops@example.com"}, csr.EmailAddresses)
}

func TestNewCSRRejectsBadIP(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = NewCSR(priv, "svc", []string{"ip:not-an-ip"})
	assert.Error(t, err, "expected error for invalid typed IP SAN")
}

func TestGenerateKey(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)

	// Key must be usable for CSR creation.
	_, err = NewCSR(priv, "test", nil)
	require.NoError(t, err)
	assert.IsType(t, ed25519.PrivateKey{}, priv)
}
