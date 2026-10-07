package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
)

const (
	caID     = "0199a0a0-0000-7000-8000-000000000002"
	targetID = "0199a0a0-0000-7000-8000-000000000003"
)

func TestFromAccess(t *testing.T) {
	t.Parallel()
	res := &nokkuv1.GetMyAccessResponse{
		Subject: &nokkuv1.GetMyAccessResponse_User{User: &nokkuv1.User{Id: new("u"), Name: new("alice")}},
		CertificateAuthorities: []*nokkuv1.CertificateAuthority{
			{Id: new(caID), Name: new("ssh"), PublicKey: new("ssh-ed25519 AAAA")},
			{
				Id:            new("0199a0a0-0000-7000-8000-000000000004"),
				AuthorityType: nokkuv1.AuthorityType_AUTHORITY_TYPE_X509.Enum(),
			},
		},
		Targets: []*nokkuv1.Target{
			{Id: new(targetID), CaId: new(caID), Name: new("web")},
			{Id: new("../../etc"), CaId: new(caID), Name: new("evil")},
			{Id: new("{" + targetID + "}"), CaId: new(caID), Name: new("braces")},
		},
	}

	c := FromAccess(res)
	require.NotNil(t, c.User)
	assert.Equal(t, "alice", c.User.Name)
	require.Len(t, c.CAs, 1, "X.509 CAs never reach the ssh snapshot")
	require.Len(t, c.Targets, 1, "non-canonical ids are dropped")
	assert.Equal(t, "web", c.Targets[0].Name)
	assert.Equal(t, caID, c.Targets[0].CAID)
}
