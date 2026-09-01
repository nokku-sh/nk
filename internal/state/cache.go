package state

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nokku-sh/nk/internal/fsutil"
	"github.com/nokku-sh/nk/internal/paths"
)

type Cache struct {
	User           *User           `json:"user,omitempty"`
	ServiceAccount *ServiceAccount `json:"service_account,omitempty"`
	Workspaces     []Workspace     `json:"workspaces,omitempty"`
	CAs            []CA            `json:"cas,omitempty"`
	Targets        []Target        `json:"targets,omitempty"`
}

func (c *Cache) Load() error {
	data, err := os.ReadFile(paths.CacheFile())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading cache: %w", err)
	}
	if err = json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("parsing cache: %w", err)
	}
	return nil
}

func (c *Cache) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing cache: %w", err)
	}
	return fsutil.WriteIfChanged(paths.CacheFile(), data, 0o600)
}
