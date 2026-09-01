package state

import (
	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
)

func MapUser(u *nokkuv1.User) *User {
	if u == nil {
		return nil
	}
	return &User{
		ID:    u.GetId(),
		Name:  u.GetName(),
		Email: u.GetEmail(),
	}
}

func MapServiceAccount(sa *nokkuv1.ServiceAccount) *ServiceAccount {
	if sa == nil {
		return nil
	}
	return &ServiceAccount{
		ID:          sa.GetId(),
		WorkspaceID: sa.GetWorkspaceId(),
		Name:        sa.GetName(),
		Description: sa.GetDescription(),
		ExpiresAt:   sa.GetExpiresAt().AsTime(),
	}
}

func MapWorkspace(ws *nokkuv1.Workspace) *Workspace {
	if ws == nil {
		return nil
	}
	return &Workspace{
		ID:          ws.GetId(),
		Name:        ws.GetName(),
		Description: ws.GetDescription(),
	}
}

func MapCA(ca *nokkuv1.CertificateAuthority) *CA {
	if ca == nil {
		return nil
	}
	return &CA{
		ID:             ca.GetId(),
		WorkspaceID:    ca.GetWorkspaceId(),
		Name:           ca.GetName(),
		PublicKey:      ca.GetPublicKey(),
		Default:        ca.GetIsDefault(),
		UserDefaultTTL: ca.GetUserDefaultTtl().AsDuration(),
		UserMaxTTL:     ca.GetUserMaxTtl().AsDuration(),
	}
}

func MapCAs(cas []*nokkuv1.CertificateAuthority) []CA {
	res := make([]CA, 0, len(cas))
	for _, ca := range cas {
		// Only SSH authorities belong in the client snapshot: X.509 CAs are
		// fetched separately and must never reach known_hosts.
		if ca != nil && ca.GetAuthorityType() != nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 {
			res = append(res, *MapCA(ca))
		}
	}
	return res
}

func MapTarget(t *nokkuv1.Target) *Target {
	if t == nil {
		return nil
	}
	return &Target{
		ID:          t.GetId(),
		WorkspaceID: t.GetWorkspaceId(),
		CAID:        t.GetCaId(),
		DaemonID:    t.GetDaemonId(),
		Name:        t.GetName(),
		Endpoints:   t.GetEndpoints(),
		Principals:  MapPrincipals(t.GetPrincipals()),
	}
}

func MapPrincipal(p *nokkuv1.Principal) *Principal {
	if p == nil {
		return nil
	}
	return &Principal{
		ID:       p.GetId(),
		Username: p.GetUsername(),
	}
}

func MapTargets(targets []*nokkuv1.Target) []Target {
	res := make([]Target, 0, len(targets))
	for _, t := range targets {
		if t != nil {
			res = append(res, *MapTarget(t))
		}
	}
	return res
}

func MapPrincipals(principals []*nokkuv1.Principal) []Principal {
	res := make([]Principal, 0, len(principals))
	for _, p := range principals {
		if p != nil {
			res = append(res, *MapPrincipal(p))
		}
	}
	return res
}
