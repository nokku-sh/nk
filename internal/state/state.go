// Package state holds the persisted session and the offline access snapshot.
package state

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mizuchilabs/kata/fsutil"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/paths"
)

// saPrefix marks service-account tokens. Unlike device sessions they
// authenticate with a plain Bearer header, without DPoP binding.
const saPrefix = "nokku_sa_"

type Workspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type ServiceAccount struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
}

type CA struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Default     bool   `json:"default,omitzero"`
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
	HostPublicKey string            `json:"host_public_key,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// Manual reports whether the target has no daemon and is synced by hand.
func (t Target) Manual() bool { return t.DaemonID == "" }

// LastManualSync is when an operator last ran nk sync, zero when never.
func (t Target) LastManualSync() time.Time {
	ts, _ := time.Parse(time.RFC3339, t.Metadata["last_manual_sync"])
	return ts
}

// Config is persisted in config.json. A session belongs to the API that issued
// it, so both live together.
type Config struct {
	APIURL           string    `json:"api_url,omitempty"`
	SessionToken     string    `json:"session_token,omitempty"`
	SessionExpiresAt time.Time `json:"session_expires_at,omitzero"`
}

// Cache is the last access snapshot, persisted in cache.json for offline use.
type Cache struct {
	User           *User           `json:"user,omitempty"`
	ServiceAccount *ServiceAccount `json:"service_account,omitempty"`
	Workspaces     []Workspace     `json:"workspaces,omitempty"`
	CAs            []CA            `json:"cas,omitempty"`
	Targets        []Target        `json:"targets,omitempty"`
}

// State is the in-memory session. Everything outside Config and Cache comes
// from flags and is never written to disk.
type State struct {
	Config
	Cache

	// Token is a service account token from --token or NK_TOKEN.
	Token      string
	TTL        time.Duration
	RequireTPM bool
	Insecure   bool
}

// FromCommand loads the persisted state and applies the global flags.
func FromCommand(cmd *cli.Command) (*State, error) {
	s := Load()
	s.Token = cmd.String("token")
	s.TTL = cmd.Duration("ttl")
	s.RequireTPM = cmd.Bool("require-tpm")
	s.Insecure = cmd.Bool("insecure")

	if s.Token != "" && !strings.HasPrefix(s.Token, saPrefix) {
		return nil, errors.New("--token (NK_TOKEN) must be a service account token starting with " + saPrefix)
	}
	if api := cmd.String("api"); s.APIURL != api && (s.APIURL == "" || cmd.IsSet("api")) {
		// Another server never gets this session or shows its targets.
		s.Config = Config{APIURL: api}
		s.Cache = Cache{}
	}
	return s, nil
}

// Load reads config and cache. A missing or corrupt file starts empty.
func Load() *State {
	s := &State{}
	if err := fsutil.LoadJSON(paths.ConfigFile(), &s.Config); err != nil {
		slog.Warn("failed to load config", "err", err)
	}
	if err := s.LoadCache(); err != nil {
		slog.Warn("failed to load cache", "err", err)
	}
	return s
}

// LoadCache replaces the in-memory snapshot with the one on disk.
func (s *State) LoadCache() error {
	s.Cache = Cache{}
	return fsutil.LoadJSON(paths.CacheFile(), &s.Cache)
}

func (s *State) Save() error {
	if err := fsutil.SaveJSON(paths.ConfigFile(), s.Config, 0o600); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	if err := fsutil.SaveJSON(paths.CacheFile(), s.Cache, 0o600); err != nil {
		return fmt.Errorf("saving cache: %w", err)
	}
	return nil
}

// IsServiceAccount reports whether a service account token is in use.
func (s *State) IsServiceAccount() bool { return s.Token != "" }

func (s *State) SessionValid() bool {
	if s.IsServiceAccount() {
		return true
	}
	if s.SessionToken == "" {
		return false
	}
	return s.SessionExpiresAt.IsZero() || time.Now().Before(s.SessionExpiresAt)
}

func (s *State) HasCachedData() bool {
	return len(s.Targets) > 0 && (s.User != nil || s.ServiceAccount != nil)
}

func (s *State) TargetByID(id string) *Target {
	for i := range s.Targets {
		if s.Targets[i].ID == id {
			return &s.Targets[i]
		}
	}
	return nil
}

func (s *State) CAByID(id string) *CA {
	for i := range s.CAs {
		if s.CAs[i].ID == id {
			return &s.CAs[i]
		}
	}
	return nil
}

func (s *State) WorkspaceName(id string) string {
	for _, w := range s.Workspaces {
		if w.ID == id {
			return w.Name
		}
	}
	return ""
}
