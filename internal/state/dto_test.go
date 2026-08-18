package state

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
)

func TestMapUser(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		if got := MapUser(nil); got != nil {
			t.Errorf("MapUser(nil) = %v, want nil", got)
		}
	})

	t.Run("maps all fields correctly", func(t *testing.T) {
		u := &nokkuv1.User{
			Id:       new("user-1"),
			Username: new("alice"),
			Email:    new("alice@example.com"),
		}
		got := MapUser(u)
		if got == nil {
			t.Fatal("MapUser returned nil")
		}
		if got.ID != "user-1" || got.Username != "alice" || got.Email != "alice@example.com" {
			t.Errorf("MapUser = %+v, want {ID:user-1 Username:alice Email:alice@example.com}", got)
		}
	})
}

func TestMapServiceAccount(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		if got := MapServiceAccount(nil); got != nil {
			t.Errorf("MapServiceAccount(nil) = %v, want nil", got)
		}
	})

	t.Run("maps all fields correctly", func(t *testing.T) {
		expiresAt := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
		sa := &nokkuv1.ServiceAccount{
			Id:          new("sa-1"),
			WorkspaceId: new("ws-1"),
			Name:        new("deploy-bot"),
			Description: new("CI/CD deployer"),
			ExpiresAt:   timestamppb.New(expiresAt),
		}
		got := MapServiceAccount(sa)
		if got == nil {
			t.Fatal("MapServiceAccount returned nil")
		}
		if got.ID != "sa-1" || got.WorkspaceID != "ws-1" || got.Name != "deploy-bot" {
			t.Errorf("MapServiceAccount = %+v", got)
		}
		if got.Description != "CI/CD deployer" || !got.ExpiresAt.Equal(expiresAt) {
			t.Errorf("MapServiceAccount description/expires mismatch")
		}
	})
}

func TestMapWorkspace(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		if got := MapWorkspace(nil); got != nil {
			t.Errorf("MapWorkspace(nil) = %v, want nil", got)
		}
	})

	t.Run("maps all fields correctly", func(t *testing.T) {
		ws := &nokkuv1.Workspace{
			Id:          new("ws-1"),
			Name:        new("production"),
			Description: new("Production environment"),
		}
		got := MapWorkspace(ws)
		if got == nil {
			t.Fatal("MapWorkspace returned nil")
		}
		if got.ID != "ws-1" || got.Name != "production" ||
			got.Description != "Production environment" {
			t.Errorf("MapWorkspace = %+v", got)
		}
	})
}

func TestMapWorkspaces(t *testing.T) {
	t.Parallel()

	t.Run("nil slice returns empty", func(t *testing.T) {
		got := MapWorkspaces(nil)
		if got == nil {
			t.Error("MapWorkspaces(nil) returned nil, want empty slice")
		}
		if len(got) != 0 {
			t.Errorf("MapWorkspaces(nil) len = %d, want 0", len(got))
		}
	})

	t.Run("empty slice returns empty", func(t *testing.T) {
		got := MapWorkspaces([]*nokkuv1.Workspace{})
		if len(got) != 0 {
			t.Errorf("MapWorkspaces(empty) len = %d, want 0", len(got))
		}
	})

	t.Run("skips nil entries", func(t *testing.T) {
		got := MapWorkspaces([]*nokkuv1.Workspace{
			{Id: new("1"), Name: new("ws-a")},
			nil,
			{Id: new("2"), Name: new("ws-b")},
		})
		if len(got) != 2 {
			t.Errorf("MapWorkspaces len = %d, want 2", len(got))
		}
	})

	t.Run("maps all entries", func(t *testing.T) {
		got := MapWorkspaces([]*nokkuv1.Workspace{
			{Id: new("1"), Name: new("prod")},
			{Id: new("2"), Name: new("staging")},
		})
		if len(got) != 2 {
			t.Fatalf("MapWorkspaces len = %d, want 2", len(got))
		}
		if got[0].Name != "prod" || got[1].Name != "staging" {
			t.Errorf("MapWorkspaces = %+v", got)
		}
	})
}

func TestMapCA(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		if got := MapCA(nil); got != nil {
			t.Errorf("MapCA(nil) = %v, want nil", got)
		}
	})

	t.Run("maps all fields correctly", func(t *testing.T) {
		ca := &nokkuv1.CertificateAuthority{
			Id:             new("ca-1"),
			WorkspaceId:    new("ws-1"),
			Name:           new("Production CA"),
			PublicKey:      new("ssh-ed25519 AAAA..."),
			IsDefault:      new(true),
			UserDefaultTtl: durationpb.New(4 * time.Hour),
			UserMaxTtl:     durationpb.New(24 * time.Hour),
		}
		got := MapCA(ca)
		if got == nil {
			t.Fatal("MapCA returned nil")
		}
		if got.ID != "ca-1" || got.WorkspaceID != "ws-1" || got.Name != "Production CA" {
			t.Errorf("MapCA basic fields = %+v", got)
		}
		if got.UserDefaultTTL != 4*time.Hour {
			t.Errorf("UserDefaultTTL = %v, want 4h", got.UserDefaultTTL)
		}
		if got.UserMaxTTL != 24*time.Hour {
			t.Errorf("UserMaxTTL = %v, want 24h", got.UserMaxTTL)
		}
	})
}

func TestMapCAs(t *testing.T) {
	t.Parallel()

	t.Run("nil slice returns empty", func(t *testing.T) {
		got := MapCAs(nil)
		if len(got) != 0 {
			t.Errorf("MapCAs(nil) len = %d, want 0", len(got))
		}
	})

	t.Run("skips nil entries", func(t *testing.T) {
		got := MapCAs([]*nokkuv1.CertificateAuthority{
			{Id: new("ca-1"), Name: new("CA A")},
			nil,
		})
		if len(got) != 1 {
			t.Errorf("MapCAs len = %d, want 1", len(got))
		}
	})
}

func TestMapTarget(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		if got := MapTarget(nil); got != nil {
			t.Errorf("MapTarget(nil) = %v, want nil", got)
		}
	})

	t.Run("maps all fields correctly", func(t *testing.T) {
		target := &nokkuv1.Target{
			Id:          new("t-1"),
			WorkspaceId: new("ws-1"),
			CaId:        new("ca-1"),
			DaemonId:    new("d-1"),
			Name:        new("web-server"),
			Endpoints:   []string{"10.0.0.1:22"},
			Principals: []*nokkuv1.Principal{
				{Id: new("p-1"), Username: new("ubuntu")},
			},
		}
		got := MapTarget(target)
		if got == nil {
			t.Fatal("MapTarget returned nil")
		}
		if got.ID != "t-1" || got.CAID != "ca-1" || got.Name != "web-server" {
			t.Errorf("MapTarget basic fields = %+v", got)
		}
		if len(got.Endpoints) != 1 || got.Endpoints[0] != "10.0.0.1:22" {
			t.Errorf("MapTarget endpoints = %v", got.Endpoints)
		}
		if len(got.Principals) != 1 || got.Principals[0].Username != "ubuntu" {
			t.Errorf("MapTarget principals = %+v", got.Principals)
		}
	})

	t.Run("nil principals become empty slice", func(t *testing.T) {
		got := MapTarget(&nokkuv1.Target{
			Id:   new("t-2"),
			Name: new("empty-target"),
		})
		if got.Principals == nil {
			t.Error("Principals should be empty slice, not nil")
		}
	})
}

func TestMapTargets(t *testing.T) {
	t.Parallel()

	t.Run("nil slice returns empty", func(t *testing.T) {
		got := MapTargets(nil)
		if len(got) != 0 {
			t.Errorf("MapTargets(nil) len = %d, want 0", len(got))
		}
	})

	t.Run("skips nil entries", func(t *testing.T) {
		got := MapTargets([]*nokkuv1.Target{
			{Id: new("t-1"), Name: new("target-a")},
			nil,
			{Id: new("t-2"), Name: new("target-b")},
		})
		if len(got) != 2 {
			t.Errorf("MapTargets len = %d, want 2", len(got))
		}
	})
}

func TestMapPrincipal(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		if got := MapPrincipal(nil); got != nil {
			t.Errorf("MapPrincipal(nil) = %v, want nil", got)
		}
	})

	t.Run("maps all fields correctly", func(t *testing.T) {
		p := &nokkuv1.Principal{
			Id:       new("p-1"),
			Username: new("admin"),
		}
		got := MapPrincipal(p)
		if got == nil {
			t.Fatal("MapPrincipal returned nil")
		}
		if got.ID != "p-1" || got.Username != "admin" {
			t.Errorf("MapPrincipal = %+v", got)
		}
	})
}

func TestMapPrincipals(t *testing.T) {
	t.Parallel()

	t.Run("nil slice returns empty", func(t *testing.T) {
		got := MapPrincipals(nil)
		if len(got) != 0 {
			t.Errorf("MapPrincipals(nil) len = %d, want 0", len(got))
		}
	})

	t.Run("skips nil entries", func(t *testing.T) {
		got := MapPrincipals([]*nokkuv1.Principal{
			{Id: new("p-1"), Username: new("user-a")},
			nil,
			{Id: new("p-2"), Username: new("user-b")},
		})
		if len(got) != 2 {
			t.Errorf("MapPrincipals len = %d, want 2", len(got))
		}
	})
}
