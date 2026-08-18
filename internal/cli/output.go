package cli

import (
	"encoding/json"
	"fmt"

	"github.com/nokku-sh/nk/internal/state"
)

// targetUsers returns the usernames of a target's principals.
func targetUsers(t state.Target) []string {
	users := make([]string, 0, len(t.Principals))
	for _, p := range t.Principals {
		users = append(users, p.Username)
	}
	return users
}

// printTargetsJSON writes the machine list as JSON, grouped by workspace.
func printTargetsJSON(s *state.State) error {
	workspaces := make(map[string]string, len(s.Workspaces))
	for _, w := range s.Workspaces {
		workspaces[w.ID] = w.Name
	}

	type target struct {
		Name      string   `json:"name"`
		Workspace string   `json:"workspace"`
		Users     []string `json:"users"`
	}
	out := struct {
		Targets []target `json:"targets"`
	}{Targets: make([]target, 0, len(s.Targets))}

	for _, t := range s.Targets {
		out.Targets = append(out.Targets, target{
			Name:      t.Name,
			Workspace: workspaces[t.WorkspaceID],
			Users:     targetUsers(t),
		})
	}
	return writeJSON(out)
}

func writeJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
