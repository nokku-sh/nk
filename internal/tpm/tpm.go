package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// signerSalt namespaces the TPM key derivation per application, so the
// daemon and CLI derive distinct keys from the same TPM. The salts in use
// are "nokku-daemon", "nokku-cli" (this value) and "nokku-ssh".
var signerSalt = []byte("nokku-cli")

// eccSignTemplate returns the deterministic ECC P-256 signing template.
// The private key exists only inside the TPM.
func eccSignTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: []byte{}},
				Y: tpm2.TPM2BECCParameter{Buffer: []byte{}},
			},
		),
	}
}

// ecdsaSignature mirrors crypto/ecdsa's internal type for DER encoding.
type ecdsaSignature struct {
	R, S *big.Int
}

// Available reports whether a TPM 2.0 device can be opened on this machine.
// The error carries the reason (missing device, permission denied, ...).
func Available() error {
	dev, err := openTPMDevice()
	if err != nil {
		return err
	}
	return dev.Close()
}

// primaryKey is a loaded deterministic primary key: a handle inside the TPM
// plus its parsed public key.
type primaryKey struct {
	hnd  tpm2.TPMHandle
	name tpm2.TPM2BName
	pub  *ecdsa.PublicKey
}

// createPrimary creates the deterministic ECC P-256 primary key for salt.
func createPrimary(r transport.TPM, salt []byte) (*primaryKey, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: salt}),
			},
		},
		InPublic: tpm2.New2B(eccSignTemplate()),
	}.Execute(r)
	if err != nil {
		return nil, fmt.Errorf("create primary key: %w", err)
	}

	pub, err := publicToECDSA(rsp.OutPublic)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(r)
		return nil, err
	}
	return &primaryKey{hnd: rsp.ObjectHandle, name: rsp.Name, pub: pub}, nil
}

// signECDSA signs a SHA-256 digest with the loaded key and returns the
// DER-encoded signature.
func signECDSA(r transport.TPM, key *primaryKey, digest []byte) ([]byte, error) {
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: key.hnd,
			Name:   key.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		// InScheme is left NULL since the template pins ECDSA. The
		// validation ticket must be explicit, as a zero ticket has
		// Tag=0, which the TPM rejects.
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(r)
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}

	ecc, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("decode tpm signature: %w", err)
	}
	return asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(ecc.SignatureR.Buffer),
		S: new(big.Int).SetBytes(ecc.SignatureS.Buffer),
	})
}

type tpmSigner struct {
	tpm    transport.TPM
	closer transport.TPMCloser
	key    *primaryKey
	pem    []byte
	mu     sync.Mutex
}

func openTPM(dir string, st *state) (crypto.Signer, error) {
	rwr, err := openTPMDevice()
	if err != nil {
		return nil, err
	}

	s, err := createTPMSigner(rwr)
	if err != nil {
		_ = rwr.Close()
		return nil, err
	}
	s.closer = rwr

	pub := string(s.pem)
	if st == nil || st.PubKey != pub {
		if st != nil && st.PubKey != "" {
			slog.Warn("TPM identity changed since last login, a new key will be re-registered")
		}
		if err = saveState(dir, &state{Method: MethodTPM, PubKey: pub}); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	return s, nil
}

// createTPMSigner creates the signing primary key on r and returns
// a signer for it. The returned signer does not own r.
func createTPMSigner(r transport.TPM) (*tpmSigner, error) {
	key, err := createPrimary(r, signerSalt)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKIXPublicKey(key.pub)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: key.hnd}.Execute(r)
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	return &tpmSigner{
		tpm: r,
		key: key,
		pem: pem.EncodeToMemory(&pem.Block{Type: pemTypePublicKey, Bytes: der}),
	}, nil
}

// Public returns the PEM-encoded PKIX public key for this signer.
func (s *tpmSigner) Public() crypto.PublicKey { return s.key.pub }

func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("tpm: unsupported hash %v (key pins SHA-256)", opts.HashFunc())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return signECDSA(s.tpm, s.key, digest)
}

func (s *tpmSigner) Close() error {
	var err error
	_, ferr := tpm2.FlushContext{FlushHandle: s.key.hnd}.Execute(s.tpm)
	err = errors.Join(err, ferr)
	if s.closer != nil {
		err = errors.Join(err, s.closer.Close())
	}
	return err
}

func publicToECDSA(pub tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	tp, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if tp.Type != tpm2.TPMAlgECC {
		return nil, errors.New("TPM key is not ECC")
	}
	point, err := tp.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("decode ECC point: %w", err)
	}
	curve := elliptic.P256()
	size := (curve.Params().BitSize + 7) / 8

	// TPM coordinates are big-endian with leading zero bytes stripped.
	// SEC 1 uncompressed form is 0x04 || X || Y with each coordinate
	// padded to the curve size.
	pad := func(b []byte) ([]byte, error) {
		if len(b) > size {
			return nil, errors.New("coordinate longer than curve size")
		}
		out := make([]byte, size)
		copy(out[size-len(b):], b)
		return out, nil
	}

	x, err := pad(point.X.Buffer)
	if err != nil {
		return nil, fmt.Errorf("parse ECC point: %w", err)
	}
	y, err := pad(point.Y.Buffer)
	if err != nil {
		return nil, fmt.Errorf("parse ECC point: %w", err)
	}

	data := make([]byte, 1+2*size)
	data[0] = 0x04
	copy(data[1:], x)
	copy(data[1+size:], y)

	key, err := ecdsa.ParseUncompressedPublicKey(curve, data)
	if err != nil {
		return nil, fmt.Errorf("parse ECC point: %w", err)
	}
	return key, nil
}
