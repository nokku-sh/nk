package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	"github.com/nokku-sh/nk/internal/state"
)

func listCMD() *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"ls"},
		Usage:   "List available machines across all workspaces",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: jsonFlag, Usage: jsonFlagUse},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			s := state.FromCommand(cmd)
			client, err := client.New(ctx, s)
			if err != nil {
				return err
			}
			err = client.SyncOrCache(ctx, true)
			if err != nil {
				return err
			}

			if cmd.Bool(jsonFlag) {
				return printTargetsJSON(s)
			}
			if len(s.Targets) == 0 {
				fmt.Println("No targets available.")
				return nil
			}

			fmt.Printf("Targets (%d):\n", len(s.Targets))
			for _, t := range s.Targets {
				users := make([]string, 0, len(t.Principals))
				for _, p := range t.Principals {
					users = append(users, p.Username)
				}
				userStr := "none"
				if len(users) > 0 {
					userStr = strings.Join(users, ", ")
				}
				fmt.Printf("-  %-20s  [Users: %s]\n", t.Name, userStr)
			}
			fmt.Println("Connect using: ssh <target-name> or ssh <user>@<target-name>")
			return nil
		},
	}
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
		users := make([]string, 0, len(t.Principals))
		for _, p := range t.Principals {
			users = append(users, p.Username)
		}
		out.Targets = append(out.Targets, target{
			Name:      t.Name,
			Workspace: workspaces[t.WorkspaceID],
			Users:     users,
		})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
