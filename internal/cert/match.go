package cert

import (
	"fmt"
	"strings"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
)

// MatchX509CA picks the CA for nameOrID from cas. An empty nameOrID selects
// the only CA, or errors when several exist. Otherwise the first CA whose ID
// matches exactly or whose name matches case-insensitively wins.
func MatchX509CA(
	cas []*nokkuv1.CertificateAuthority,
	nameOrID string,
) (*nokkuv1.CertificateAuthority, error) {
	if len(cas) == 0 {
		return nil, fmt.Errorf("no X.509 certificate authorities available")
	}
	if nameOrID == "" {
		if len(cas) > 1 {
			return nil, fmt.Errorf("multiple X.509 CAs available, specify one with --ca")
		}
		return cas[0], nil
	}
	for _, ca := range cas {
		if ca.GetId() == nameOrID || strings.EqualFold(ca.GetName(), nameOrID) {
			return ca, nil
		}
	}
	return nil, fmt.Errorf("X.509 CA %q not found", nameOrID)
}
