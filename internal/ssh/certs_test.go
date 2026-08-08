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
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	certDir := util.CertPath()
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := CleanupCerts(nil); err != nil {
		t.Fatalf("CleanupCerts(nil) error = %v", err)
	}
}

func TestVerifyCertificateByID(t *testing.T) {
	setupSSHDir(t)

	certDir := util.CertPath()
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Run("file not found", func(t *testing.T) {
		err := VerifyCertificateByID("nonexistent-ca")
		if err == nil {
			t.Error("expected error for missing certificate file")
		}
	})

	t.Run("invalid cert file", func(t *testing.T) {
		path := util.Certificate("bad-ca")
		if err := os.WriteFile(path, []byte("not-a-cert"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := VerifyCertificateByID("bad-ca")
		if err == nil {
			t.Error("expected error for invalid certificate file")
		}
	})
}
