package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
)

func TestMapUser(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		assert.Nil(t, MapUser(nil))
	})

	t.Run("maps all fields correctly", func(t *testing.T) {
		u := &nokkuv1.User{
			Id:    new("user-1"),
			Name:  new("alice"),
			Email: new("alice@example.com"),
		}
		got := MapUser(u)
		require.NotNil(t, got)
		assert.Equal(t, &User{ID: "user-1", Name: "alice", Email: "alice@example.com"}, got)
	})
}

func TestMapServiceAccount(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		assert.Nil(t, MapServiceAccount(nil))
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
		require.NotNil(t, got)
		assert.Equal(t, &ServiceAccount{
			ID:          "sa-1",
			WorkspaceID: "ws-1",
			Name:        "deploy-bot",
			Description: "CI/CD deployer",
			ExpiresAt:   expiresAt,
		}, got)
	})
}

func TestMapWorkspace(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		assert.Nil(t, MapWorkspace(nil))
	})

	t.Run("maps all fields correctly", func(t *testing.T) {
		ws := &nokkuv1.Workspace{
			Id:          new("ws-1"),
			Name:        new("production"),
			Description: new("Production environment"),
		}
		got := MapWorkspace(ws)
		require.NotNil(t, got)
		assert.Equal(t, &Workspace{ID: "ws-1", Name: "production", Description: "Production environment"}, got)
	})
}

func TestMapCA(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		assert.Nil(t, MapCA(nil))
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
		require.NotNil(t, got)
		assert.Equal(t, "ca-1", got.ID)
		assert.Equal(t, "ws-1", got.WorkspaceID)
		assert.Equal(t, "Production CA", got.Name)
		assert.Equal(t, "ssh-ed25519 AAAA...", got.PublicKey)
		assert.Equal(t, 4*time.Hour, got.UserDefaultTTL)
		assert.Equal(t, 24*time.Hour, got.UserMaxTTL)
	})
}

func TestMapCAs(t *testing.T) {
	t.Parallel()

	t.Run("nil slice returns empty", func(t *testing.T) {
		assert.Empty(t, MapCAs(nil))
	})

	t.Run("skips nil entries", func(t *testing.T) {
		got := MapCAs([]*nokkuv1.CertificateAuthority{
			{Id: new("ca-1"), Name: new("CA A")},
			nil,
		})
		assert.Len(t, got, 1)
	})
}

func TestMapTarget(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		assert.Nil(t, MapTarget(nil))
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
		require.NotNil(t, got)
		assert.Equal(t, "t-1", got.ID)
		assert.Equal(t, "ca-1", got.CAID)
		assert.Equal(t, "web-server", got.Name)
		assert.Equal(t, []string{"10.0.0.1:22"}, got.Endpoints)
		assert.Equal(t, []Principal{{ID: "p-1", Username: "ubuntu"}}, got.Principals)
	})

	t.Run("nil principals become empty slice", func(t *testing.T) {
		got := MapTarget(&nokkuv1.Target{
			Id:   new("t-2"),
			Name: new("empty-target"),
		})
		assert.Empty(t, got.Principals)
		assert.NotNil(t, got.Principals)
	})
}

func TestMapTargets(t *testing.T) {
	t.Parallel()

	t.Run("nil slice returns empty", func(t *testing.T) {
		assert.Empty(t, MapTargets(nil))
	})

	t.Run("skips nil entries", func(t *testing.T) {
		got := MapTargets([]*nokkuv1.Target{
			{Id: new("t-1"), Name: new("target-a")},
			nil,
			{Id: new("t-2"), Name: new("target-b")},
		})
		assert.Len(t, got, 2)
	})
}

func TestMapPrincipal(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		assert.Nil(t, MapPrincipal(nil))
	})

	t.Run("maps all fields correctly", func(t *testing.T) {
		p := &nokkuv1.Principal{
			Id:       new("p-1"),
			Username: new("admin"),
		}
		got := MapPrincipal(p)
		require.NotNil(t, got)
		assert.Equal(t, &Principal{ID: "p-1", Username: "admin"}, got)
	})
}

func TestMapPrincipals(t *testing.T) {
	t.Parallel()

	t.Run("nil slice returns empty", func(t *testing.T) {
		assert.Empty(t, MapPrincipals(nil))
	})

	t.Run("skips nil entries", func(t *testing.T) {
		got := MapPrincipals([]*nokkuv1.Principal{
			{Id: new("p-1"), Username: new("user-a")},
			nil,
			{Id: new("p-2"), Username: new("user-b")},
		})
		assert.Len(t, got, 2)
	})
}
