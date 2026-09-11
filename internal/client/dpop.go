package client

import (
	"github.com/nokku-sh/mon/dpop"
	"github.com/nokku-sh/mon/tpm"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

// SignerSalt namespaces the CLI's machine signing key, so every Nokku binary
// derives its own.
var SignerSalt = []byte("nokku-cli")

// newProofer builds the CLI's DPoP proofer from the machine signing key,
// TPM-backed when available and otherwise the machine-wrapped software key.
// It recovers a changed identity so an interactive CLI keeps working after a
// re-image.
func newProofer(s *state.State) (*dpop.Proofer, error) {
	signer, err := tpm.NewSigner(tpm.SignerOptions{
		Salt:             SignerSalt,
		StatePath:        paths.SignerStateFile(),
		RequireTPM:       s.RequireTPM,
		OnIdentityChange: tpm.RecreateIdentity,
	})
	if err != nil {
		return nil, err
	}
	return dpop.NewProofer(signer, dpop.ProoferOptions{})
}
