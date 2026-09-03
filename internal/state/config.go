package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nokku-sh/nk/internal/fsutil"
	"github.com/nokku-sh/nk/internal/paths"
)

type Config struct {
	APIURL string        `json:"api_url,omitempty"`
	TTL    time.Duration `json:"ttl,omitempty"`
	// SessionToken is the DPoP-bound session token obtained from the device
	// flow. It is persisted (0600) so the CLI works across invocations;
	// stealing it is useless without the bound signing key.
	SessionToken string `json:"session_token,omitempty"`
	// SessionExpiresAt is when the persisted session token stops being
	// valid. Zero means unknown (re-login via device flow).
	// #nosec G117 -- session_token is a credential persisted to a 0600 file.
	SessionExpiresAt time.Time `json:"session_expires_at"`
}

func (c *Config) Load() error {
	data, err := os.ReadFile(paths.ConfigFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading config: %w", err)
	}
	if err = json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}
	return nil
}

func (c *Config) Save() error {
	// #nosec G117 -- the session token is a bearer credential persisted to a
	// 0600 file, never logged; it is useless without the bound signing key.
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing config: %w", err)
	}
	return fsutil.WriteIfChanged(paths.ConfigFile(), data, 0o600)
}
