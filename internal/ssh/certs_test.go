package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

func signCert(t testing.TB, signer ssh.Signer, validAfter, validBefore time.Time) []byte {
	t.Helper()
	c := &ssh.Certificate{
		Key:         signer.PublicKey(),
		CertType:    ssh.UserCert,
		ValidAfter:  uint64(validAfter.Unix()),
		ValidBefore: uint64(validBefore.Unix()),
	}
	require.NoError(t, c.SignCert(rand.Reader, signer))
	return ssh.MarshalAuthorizedKey(c)
}

func newSigner(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

func TestCheckCert(t *testing.T) {
	t.Parallel()
	ca, other := newSigner(t), newSigner(t)
	caKey := string(ssh.MarshalAuthorizedKey(ca.PublicKey()))
	now := time.Now()

	tests := []struct {
		name string
		cert []byte
		ok   bool
	}{
		{"valid", signCert(t, ca, now.Add(-time.Hour), now.Add(time.Hour)), true},
		{"inside the margin", signCert(t, ca, now.Add(-time.Hour), now.Add(5*time.Minute)), false},
		{"expired", signCert(t, ca, now.Add(-2*time.Hour), now.Add(-time.Hour)), false},
		{"not yet valid", signCert(t, ca, now.Add(time.Hour), now.Add(2*time.Hour)), false},
		{"other ca", signCert(t, other, now.Add(-time.Hour), now.Add(time.Hour)), false},
		{"plain key", ssh.MarshalAuthorizedKey(ca.PublicKey()), false},
		{"garbage", []byte("not-a-cert"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckCert(tt.cert, caKey, 15*time.Minute)
			assert.Equal(t, tt.ok, err == nil, "CheckCert error: %v", err)
		})
	}
}

func TestCertFresh(t *testing.T) {
	setupSSHDir(t)
	signer := newSigner(t)
	ca := state.CA{
		ID:        "0199a0a0-0000-7000-8000-000000000002",
		PublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	}
	assert.False(t, CertFresh(ca), "no certificate yet")

	now := time.Now()
	tests := []struct {
		name          string
		after, before time.Time
		signer        ssh.Signer
		fresh         bool
	}{
		{"first half of its life", now.Add(-time.Hour), now.Add(119 * time.Hour), signer, true},
		{"second half, still valid", now.Add(-61 * time.Hour), now.Add(59 * time.Hour), signer, false},
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), signer, false},
		{"other ca", now.Add(-time.Hour), now.Add(119 * time.Hour), newSigner(t), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(
				paths.SSHCertificate(ca.ID), signCert(t, tt.signer, tt.after, tt.before), 0o600,
			))
			assert.Equal(t, tt.fresh, CertFresh(ca))
		})
	}
}

func TestCertValidAndCleanup(t *testing.T) {
	setupSSHDir(t)
	signer := newSigner(t)
	keep := state.CA{
		ID:        "0199a0a0-0000-7000-8000-000000000002",
		PublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	}
	drop := state.CA{ID: "0199a0a0-0000-7000-8000-000000000009"}
	now := time.Now()
	require.NoError(
		t,
		os.WriteFile(
			paths.SSHCertificate(keep.ID),
			signCert(t, signer, now.Add(-time.Hour), now.Add(time.Hour)),
			0o600,
		),
	)
	require.NoError(t, os.WriteFile(paths.SSHCertificate(drop.ID), []byte("x"), 0o600))

	assert.True(t, CertValid(keep, 0))
	assert.False(t, CertValid(drop, 0))

	require.NoError(t, CleanupCerts([]state.CA{keep}))
	files, err := paths.SSHCertificates()
	require.NoError(t, err)
	assert.Equal(t, []string{paths.SSHCertificate(keep.ID)}, files)
}
