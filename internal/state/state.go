// Package state provides user authentication state and workspace context.
package state

import (
	"fmt"
	"log/slog"
	"time"
)

type Workspace struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type ServiceAccount struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspace_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type CA struct {
	ID             string        `json:"id"`
	WorkspaceID    string        `json:"workspace_id"`
	Name           string        `json:"name"`
	PublicKey      string        `json:"public_key"`
	Default        bool          `json:"default"`
	UserDefaultTTL time.Duration `json:"user_default_ttl"`
	UserMaxTTL     time.Duration `json:"user_max_ttl"`
}

type Target struct {
	ID          string   `json:"id"`
	WorkspaceID string   `json:"workspace_id"`
	CAID        string   `json:"ca_id,omitempty"`
	DaemonID    string   `json:"daemon_id,omitempty"`
	Name        string   `json:"name"`
	Endpoints   []string `json:"endpoints,omitempty"`
	// Usernames are the accounts this subject may log in as on the target.
	Usernames []string `json:"usernames,omitempty"`
	// HostPublicKey pins the host key of a manual target.
	HostPublicKey string `json:"host_public_key,omitempty"`
}

// State is the in-memory session, combining persisted config and offline cache.
type State struct {
	Config
	Cache

	// Token is a service account token from --token or NK_TOKEN. Ephemeral
	// on purpose, so it is never written to disk.
	Token string

	// RequireTPM mirrors the --require-tpm flag and refuses the software
	// key fallback. Ephemeral like Token.
	RequireTPM bool

	// Insecure mirrors the --insecure flag. Ephemeral so a TLS downgrade
	// cannot outlive the invocation that asked for it.
	Insecure bool
}

func New() *State {
	s := &State{}

	if err := s.Config.Load(); err != nil {
		slog.Warn("failed to load config", "err", err)
	}
	if err := s.Cache.Load(); err != nil {
		slog.Warn("failed to load cache", "err", err)
	}

	return s
}

func (s *State) Save() error {
	if err := s.Config.Save(); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	if err := s.Cache.Save(); err != nil {
		return fmt.Errorf("saving cache: %w", err)
	}
	return nil
}

func (s *State) SessionValid() bool {
	if s.IsServiceAccount() {
		return s.Token != ""
	}
	if s.SessionToken == "" {
		return false
	}
	return s.SessionExpiresAt.IsZero() || time.Now().Before(s.SessionExpiresAt)
}

func (s *State) HasCachedData() bool {
	return len(s.Targets) > 0 && (s.User != nil || s.ServiceAccount != nil)
}

func (s *State) TargetsByName(name string) []*Target {
	var matches []*Target
	for i := range s.Targets {
		if s.Targets[i].Name == name {
			matches = append(matches, &s.Targets[i])
		}
	}
	return matches
}

func (s *State) CAByID(id string) *CA {
	for i := range s.CAs {
		if s.CAs[i].ID == id {
			return &s.CAs[i]
		}
	}
	return nil
}
