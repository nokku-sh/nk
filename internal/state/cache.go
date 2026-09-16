package state

import (
	"github.com/nokku-sh/mon/fsutil"

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
	return fsutil.LoadJSON(paths.CacheFile(), c)
}

func (c *Cache) Save() error {
	return fsutil.SaveJSON(paths.CacheFile(), c, 0o600)
}
