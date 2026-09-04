package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nk/internal/paths"
)

func signCert(t *testing.T, signer ssh.Signer, validAfter, validBefore uint64) []byte {
	t.Helper()
	c := &ssh.Certificate{
		Key:         signer.PublicKey(),
		CertType:    ssh.UserCert,
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
	}
	require.NoError(t, c.SignCert(rand.Reader, signer))
	return ssh.MarshalAuthorizedKey(c)
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

func TestVerifyCertificate(t *testing.T) {
	t.Parallel()
	signer := newSigner(t)
	now := time.Now()

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid certificate",
			data:    signCert(t, signer, uint64(now.Add(-time.Hour).Unix()), uint64(now.Add(time.Hour).Unix())),
			wantErr: false,
		},
		{
			name:    "expired certificate",
			data:    signCert(t, signer, uint64(now.Add(-2*time.Hour).Unix()), uint64(now.Add(-time.Hour).Unix())),
			wantErr: true,
		},
		{
			name:    "valid until the last second",
			data:    signCert(t, signer, uint64(now.Add(-time.Hour).Unix()), uint64(now.Add(5*time.Minute).Unix())),
			wantErr: false,
		},
		{
			name:    "not a certificate (plain key)",
			data:    bytes.TrimSpace(ssh.MarshalAuthorizedKey(signer.PublicKey())),
			wantErr: true,
		},
		{
			name:    "invalid data",
			data:    []byte("not-a-cert"),
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyCertificate(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCleanupCerts_NoMatches(t *testing.T) {
	setupSSHDir(t)
	require.NoError(t, CleanupCerts(nil))
}

func TestCertificateFresh(t *testing.T) {
	setupSSHDir(t)

	certDir := paths.SSHCertPath()
	require.NoError(t, os.MkdirAll(certDir, 0o700))

	signer := newSigner(t)
	caPub := ssh.MarshalAuthorizedKey(signer.PublicKey())
	otherSigner := newSigner(t)

	const margin = 15 * time.Minute
	now := uint64(time.Now().Add(-time.Hour).Unix())

	t.Run("file not found", func(t *testing.T) {
		assert.False(t, CertificateFresh("nonexistent-ca", string(caPub), margin),
			"expected false for missing certificate file")
	})

	t.Run("invalid cert file", func(t *testing.T) {
		path := paths.SSHCertificate("bad-ca")
		require.NoError(t, os.WriteFile(path, []byte("not-a-cert"), 0o600))
		assert.False(t, CertificateFresh("bad-ca", string(caPub), margin),
			"expected false for invalid certificate file")
	})

	t.Run("cert signed by current CA is fresh", func(t *testing.T) {
		path := paths.SSHCertificate("good-ca")
		require.NoError(t, os.WriteFile(
			path,
			signCert(t, signer, now, uint64(time.Now().Add(time.Hour).Unix())),
			0o600,
		))
		assert.True(t, CertificateFresh("good-ca", string(caPub), margin),
			"expected true for cert signed by current CA")
	})

	t.Run("cert within the renewal window is stale", func(t *testing.T) {
		path := paths.SSHCertificate("soon-ca")
		require.NoError(t, os.WriteFile(
			path,
			signCert(t, signer, now, uint64(time.Now().Add(5*time.Minute).Unix())),
			0o600,
		))
		assert.False(t, CertificateFresh("soon-ca", string(caPub), margin),
			"expected false for cert expiring within the margin")
	})

	t.Run("cert signed by a retired CA is rejected", func(t *testing.T) {
		path := paths.SSHCertificate("rolled-ca")
		require.NoError(t, os.WriteFile(
			path,
			signCert(t, otherSigner, now, uint64(time.Now().Add(time.Hour).Unix())),
			0o600,
		))
		assert.False(t, CertificateFresh("rolled-ca", string(caPub), margin),
			"expected false for cert signed by a different CA")
	})
}
