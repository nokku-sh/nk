package state

import (
	"time"

	"github.com/nokku-sh/nk/internal/paths"
)

type Config struct {
	APIURL string        `json:"api_url,omitempty"`
	TTL    time.Duration `json:"ttl,omitempty"`
	// SessionToken is the DPoP-bound device session token, persisted so the
	// CLI works across invocations.
	SessionToken string `json:"session_token,omitempty"`
	// SessionExpiresAt is when the persisted session token stops being
	// valid. Zero means unknown, so log in again.
	SessionExpiresAt time.Time `json:"session_expires_at"`
}

func (c *Config) Load() error {
	return loadJSON(paths.ConfigFile(), c)
}

func (c *Config) Save() error {
	return saveJSON(paths.ConfigFile(), c)
}
