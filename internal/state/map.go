package state

import (
	"log/slog"
	"uuid"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
)

// FromAccess maps the backend access snapshot. IDs end up in file paths and
// generated ssh files, so anything that is not a UUID is dropped here, once.
func FromAccess(res *nokkuv1.GetMyAccessResponse) Cache {
	var c Cache
	switch subject := res.GetSubject().(type) {
	case *nokkuv1.GetMyAccessResponse_User:
		u := subject.User
		c.User = &User{ID: u.GetId(), Name: u.GetName(), Email: u.GetEmail()}
	case *nokkuv1.GetMyAccessResponse_ServiceAccount:
		sa := subject.ServiceAccount
		c.ServiceAccount = &ServiceAccount{ID: sa.GetId(), WorkspaceID: sa.GetWorkspaceId(), Name: sa.GetName()}
	}

	for _, wa := range res.GetWorkspaces() {
		if !validIDs(wa.GetWorkspaceId()) {
			continue
		}
		c.Workspaces = append(c.Workspaces, Workspace{ID: wa.GetWorkspaceId(), Name: wa.GetWorkspaceName()})
		for _, ca := range wa.GetCertificateAuthorities() {
			// X.509 CAs are fetched separately and must never reach known_hosts.
			if ca.GetAuthorityType() == nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 || !validIDs(ca.GetId()) {
				continue
			}
			c.CAs = append(c.CAs, CA{
				ID:          ca.GetId(),
				WorkspaceID: wa.GetWorkspaceId(),
				Name:        ca.GetName(),
				PublicKey:   ca.GetPublicKey(),
				Default:     ca.GetIsDefault(),
			})
		}
		for _, t := range wa.GetTargets() {
			if !validIDs(t.GetId(), t.GetCaId()) || t.GetDaemonId() != "" && !validIDs(t.GetDaemonId()) {
				continue
			}
			tgt := MapTarget(t)
			tgt.WorkspaceID = wa.GetWorkspaceId()
			c.Targets = append(c.Targets, tgt)
		}
	}
	return c
}

func MapTarget(t *nokkuv1.Target) Target {
	return Target{
		ID:            t.GetId(),
		WorkspaceID:   t.GetWorkspaceId(),
		CAID:          t.GetCaId(),
		DaemonID:      t.GetDaemonId(),
		Name:          t.GetName(),
		Endpoints:     t.GetEndpoints(),
		Usernames:     t.GetUsernames(),
		HostPublicKey: t.GetHostPublicKey(),
		Metadata:      t.GetMetadata(),
	}
}

func validIDs(ids ...string) bool {
	for _, id := range ids {
		// Only the canonical form, which is safe as a path segment and ssh token.
		if u, err := uuid.Parse(id); err != nil || u.String() != id {
			slog.Warn("ignoring backend entry with an invalid id", "id", id)
			return false
		}
	}
	return true
}
