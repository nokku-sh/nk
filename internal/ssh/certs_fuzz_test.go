package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nk/internal/util"
)

// FuzzVerifyCertificate feeds arbitrary bytes into the certificate
// validity checker. It must never panic, and anything it accepts must
// be a certificate valid at the current time.
func FuzzVerifyCertificate(f *testing.F) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		f.Fatalf("signer: %v", err)
	}

	sign := func(validAfter, validBefore uint64) []byte {
		c := &ssh.Certificate{
			Key:         signer.PublicKey(),
			CertType:    ssh.UserCert,
			ValidAfter:  validAfter,
			ValidBefore: validBefore,
		}
		if err = c.SignCert(rand.Reader, signer); err != nil {
			f.Fatalf("sign cert: %v", err)
		}
		return ssh.MarshalAuthorizedKey(c)
	}

	now := time.Now()
	seeds := [][]byte{
		sign(uint64(now.Add(-time.Hour).Unix()), uint64(now.Add(time.Hour).Unix())),
		sign(uint64(now.Add(-2*time.Hour).Unix()), uint64(now.Add(-time.Hour).Unix())),
		sign(0, ssh.CertTimeInfinity),
		ssh.MarshalAuthorizedKey(signer.PublicKey()),
		[]byte(""),
		[]byte("not-a-cert"),
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		checkErr := VerifyCertificate(data)
		if checkErr != nil {
			return
		}

		pub, _, _, _, perr := ssh.ParseAuthorizedKey(data)
		if perr != nil {
			t.Fatalf("VerifyCertificate accepted unparseable data: %v", perr)
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			t.Fatalf("VerifyCertificate accepted a non-certificate")
		}
		// The validator's own acceptance rule: now must fall inside the
		// certificate's validity window.
		if time.Now().Before(util.Uint64ToUnixTime(cert.ValidAfter)) ||
			time.Now().After(util.Uint64ToUnixTime(cert.ValidBefore)) {
			t.Fatalf("VerifyCertificate accepted a certificate outside its validity window")
		}
	})
}
