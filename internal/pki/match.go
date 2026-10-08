package pki

import (
	"errors"
	"fmt"
	"strings"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
)

// MatchCA picks the CA for nameOrID from cas. An empty nameOrID selects the
// only CA, or errors when several exist. Otherwise an ID wins, then an exact
// name, then a name that matches without its case. Names are not unique on the
// backend, so a name that fits several CAs is refused.
func MatchCA(
	cas []*nokkuv1.CertificateAuthority,
	nameOrID string,
) (*nokkuv1.CertificateAuthority, error) {
	if len(cas) == 0 {
		return nil, errors.New("no X.509 certificate authorities available")
	}
	if nameOrID == "" {
		if len(cas) > 1 {
			return nil, fmt.Errorf("multiple X.509 CAs available, specify one with --ca")
		}
		return cas[0], nil
	}

	var exact, folded []*nokkuv1.CertificateAuthority
	for _, ca := range cas {
		switch {
		case ca.GetId() == nameOrID:
			return ca, nil
		case ca.GetName() == nameOrID:
			exact = append(exact, ca)
		case strings.EqualFold(ca.GetName(), nameOrID):
			folded = append(folded, ca)
		}
	}
	found := exact
	if len(found) == 0 {
		found = folded
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("X.509 CA %q not found", nameOrID)
	case 1:
		return found[0], nil
	}
	return nil, fmt.Errorf("several X.509 CAs are named %q, pass the ID", nameOrID)
}
