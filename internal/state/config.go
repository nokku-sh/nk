package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nokku-sh/nk/internal/util"
)

type Config struct {
	APIURL  string `json:"api_url,omitempty"`
	KeyType string `json:"key_type,omitempty"`
	// DeviceID is the CLI device's identity, generated on first run and
	// bound to the signing key registered with the backend.
	DeviceID string        `json:"device_id,omitempty"`
	TTL      time.Duration `json:"ttl,omitempty"`
	Insecure bool          `json:"insecure,omitempty"`
}

func (c *Config) Load() error {
	data, err := os.ReadFile(util.ConfigFile())
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
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing config: %w", err)
	}
	return util.WriteIfChanged(util.ConfigFile(), data, 0o600)
}

func (c *Config) Clear() {
	*c = Config{}
}
