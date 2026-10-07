package state

import (
	"log/slog"
	"uuid"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
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
		c.ServiceAccount = &ServiceAccount{ID: sa.GetId(), Name: sa.GetName()}
	}

	for _, ca := range res.GetCertificateAuthorities() {
		// X.509 CAs are fetched separately and must never reach known_hosts.
		if ca.GetAuthorityType() == nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 || !validIDs(ca.GetId()) {
			continue
		}
		entry := CA{
			ID:        ca.GetId(),
			Name:      ca.GetName(),
			PublicKey: ca.GetPublicKey(),
			Default:   ca.GetIsDefault(),
		}
		// AsTime turns an unset timestamp into 1970, not the zero time.
		if ca.GetNotBefore() != nil {
			entry.RotatedAt = ca.GetNotBefore().AsTime()
		}
		if ca.GetPreviousTrustedUntil() != nil {
			entry.PreviousPublicKey = ca.GetPreviousPublicKey()
			entry.PreviousTrustedUntil = ca.GetPreviousTrustedUntil().AsTime()
		}
		c.CAs = append(c.CAs, entry)
	}
	for _, t := range res.GetTargets() {
		if !validIDs(t.GetId(), t.GetCaId()) || t.GetDaemonId() != "" && !validIDs(t.GetDaemonId()) {
			continue
		}
		c.Targets = append(c.Targets, MapTarget(t))
	}
	return c
}

func MapTarget(t *nokkuv1.Target) Target {
	return Target{
		ID:            t.GetId(),
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
