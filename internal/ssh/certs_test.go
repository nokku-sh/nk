package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nk/internal/util"
)

func TestVerifyCertificate(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	sshPub := signer.PublicKey()

	now := time.Now()

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name: "valid certificate",
			data: func() []byte {
				c := &ssh.Certificate{
					Key:      sshPub,
					CertType: ssh.UserCert,

					ValidAfter: uint64(now.Add(-1 * time.Hour).Unix()),

					ValidBefore: uint64(now.Add(1 * time.Hour).Unix()),
				}
				if err = c.SignCert(rand.Reader, signer); err != nil {
					panic(err)
				}
				return ssh.MarshalAuthorizedKey(c)
			}(),
			wantErr: false,
		},
		{
			name: "expired certificate",
			data: func() []byte {
				c := &ssh.Certificate{
					Key:      sshPub,
					CertType: ssh.UserCert,

					ValidAfter: uint64(now.Add(-2 * time.Hour).Unix()),

					ValidBefore: uint64(now.Add(-1 * time.Hour).Unix()),
				}
				if err = c.SignCert(rand.Reader, signer); err != nil {
					panic(err)
				}
				return ssh.MarshalAuthorizedKey(c)
			}(),
			wantErr: true,
		},
		{
			name: "valid until the last second",
			data: func() []byte {
				c := &ssh.Certificate{
					Key:      sshPub,
					CertType: ssh.UserCert,

					ValidAfter: uint64(now.Add(-1 * time.Hour).Unix()),

					ValidBefore: uint64(now.Add(5 * time.Minute).Unix()),
				}
				if err = c.SignCert(rand.Reader, signer); err != nil {
					panic(err)
				}
				return ssh.MarshalAuthorizedKey(c)
			}(),
			wantErr: false,
		},
		{
			name:    "not a certificate (plain key)",
			data:    bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPub)),
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
			err = VerifyCertificate(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCleanupCerts_NoMatches(t *testing.T) {
	setupSSHDir(t)

	if err := CleanupCerts(nil); err != nil {
		t.Fatalf("CleanupCerts(nil) error = %v", err)
	}
}

func TestCertificateFresh(t *testing.T) {
	setupSSHDir(t)

	certDir := util.SSHCertPath()
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}

	_, priv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		t.Fatal(genErr)
	}
	signer, genErr := ssh.NewSignerFromKey(priv)
	if genErr != nil {
		t.Fatal(genErr)
	}
	caPub := ssh.MarshalAuthorizedKey(signer.PublicKey())

	signCert := func(s ssh.Signer, validFor time.Duration) []byte {
		t.Helper()
		c := &ssh.Certificate{
			Key:         signer.PublicKey(),
			CertType:    ssh.UserCert,
			ValidAfter:  uint64(time.Now().Add(-time.Hour).Unix()),
			ValidBefore: uint64(time.Now().Add(validFor).Unix()),
		}
		if signErr := c.SignCert(rand.Reader, s); signErr != nil {
			t.Fatal(signErr)
		}
		return ssh.MarshalAuthorizedKey(c)
	}

	const margin = 15 * time.Minute

	t.Run("file not found", func(t *testing.T) {
		if CertificateFresh("nonexistent-ca", string(caPub), margin) {
			t.Error("expected false for missing certificate file")
		}
	})

	t.Run("invalid cert file", func(t *testing.T) {
		path := util.SSHCertificate("bad-ca")
		if writeErr := os.WriteFile(path, []byte("not-a-cert"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		if CertificateFresh("bad-ca", string(caPub), margin) {
			t.Error("expected false for invalid certificate file")
		}
	})

	t.Run("cert signed by current CA is fresh", func(t *testing.T) {
		path := util.SSHCertificate("good-ca")
		if writeErr := os.WriteFile(path, signCert(signer, time.Hour), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		if !CertificateFresh("good-ca", string(caPub), margin) {
			t.Error("expected true for cert signed by current CA")
		}
	})

	t.Run("cert within the renewal window is stale", func(t *testing.T) {
		path := util.SSHCertificate("soon-ca")
		if writeErr := os.WriteFile(path, signCert(signer, 5*time.Minute), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		if CertificateFresh("soon-ca", string(caPub), margin) {
			t.Error("expected false for cert expiring within the margin")
		}
	})

	t.Run("cert signed by a retired CA is rejected", func(t *testing.T) {
		_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		otherSigner, err := ssh.NewSignerFromKey(otherPriv)
		if err != nil {
			t.Fatal(err)
		}
		path := util.SSHCertificate("rolled-ca")
		if writeErr := os.WriteFile(
			path,
			signCert(otherSigner, time.Hour),
			0o600,
		); writeErr != nil {
			t.Fatal(writeErr)
		}
		if CertificateFresh("rolled-ca", string(caPub), margin) {
			t.Error("expected false for cert signed by a different CA")
		}
	})
}
