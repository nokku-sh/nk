// Package tpm provides machine-bound signing identities backed by a
// TPM 2.0, with a software fallback for machines without one.
package tpm

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nokku-sh/nk/internal/util"
)

var errNoState = errors.New("no signer state")

const (
	// MethodTPM identifies a TPM-backed signing key.
	MethodTPM = "tpm"
	// MethodSoft identifies a software signing key wrapped to the machine.
	MethodSoft = "soft"

	stateFile = "signer.json"

	pemTypePublicKey = "PUBLIC KEY"
)

// state is the on-disk representation of a signer. Only public material is
// stored for TPM keys. Software keys also carry their wrapped private key.
type state struct {
	Method string `json:"method"`
	PubKey string `json:"pubkey"`
	Salt   []byte `json:"salt,omitempty"`
	Nonce  []byte `json:"nonce,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

// New loads or creates the machine's signing identity in dir, using a
// TPM when available and a software key otherwise. requireTPM makes a
// missing TPM an error. The returned key implements [crypto.Signer]; a
// TPM key's resources are reclaimed when the process exits.
func New(dir string, requireTPM bool) (crypto.Signer, error) {
	st, err := loadState(dir)
	if err != nil && !errors.Is(err, errNoState) {
		return nil, err
	}

	if st != nil {
		switch st.Method {
		case MethodTPM:
			s, tpmErr := openTPM(dir, st)
			if tpmErr != nil {
				return nil, fmt.Errorf("tpm signer: %w", tpmErr)
			}
			return s, nil
		case MethodSoft:
			if requireTPM {
				return nil, errors.New("require-tpm set, but no TPM available")
			}
			s, softErr := openSoft(dir, st)
			if softErr != nil {
				return nil, fmt.Errorf("software signer: %w", softErr)
			}
			return s, nil
		default:
			return nil, fmt.Errorf("unknown signer method %q", st.Method)
		}
	}

	s, err := openTPM(dir, nil)
	if err == nil {
		return s, nil
	}
	if requireTPM {
		return nil, fmt.Errorf("no TPM available: %w", err)
	}
	s, err = openSoft(dir, nil)
	if err != nil {
		return nil, fmt.Errorf("software signer: %w", err)
	}
	return s, nil
}

func statePath(dir string) string {
	return filepath.Join(dir, stateFile)
}

// SignerMethod reports the signing method in use (MethodTPM or MethodSoft)
// without loading or creating any key material. It returns "" when no signer
// identity exists on this machine yet.
func SignerMethod(dir string) string {
	st, err := loadState(dir)
	if err != nil || st == nil {
		return ""
	}
	return st.Method
}

func loadState(dir string) (*state, error) {
	data, err := os.ReadFile(statePath(dir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errNoState
		}
		return nil, fmt.Errorf("read signer state: %w", err)
	}
	var st state
	if err = json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse signer state: %w", err)
	}
	return &st, nil
}

func saveState(dir string, st *state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize signer state: %w", err)
	}
	if err = util.WriteIfChanged(statePath(dir), data, 0o600); err != nil {
		return fmt.Errorf("write signer state: %w", err)
	}
	return nil
}
