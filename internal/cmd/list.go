package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/ui"
)

// manualSuffix describes a daemonless target's sync age for list output.
func manualSuffix(t state.Target) string {
	if t.DaemonID != "" {
		return ""
	}
	ts, err := time.Parse(time.RFC3339, t.Metadata["last_manual_sync"])
	if err != nil {
		return "(manual, never synced)"
	}
	return "(manual, synced " + ui.HumanizeDuration(time.Since(ts)) + ")"
}

func listCMD() *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"ls"},
		Usage:   "List available machines across all workspaces",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: jsonFlag, Usage: jsonFlagUse},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			_, s, err := connect(ctx, cmd, true)
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
				userStr := "none"
				if len(t.Usernames) > 0 {
					userStr = strings.Join(t.Usernames, ", ")
				}
				line := fmt.Sprintf("-  %-20s  [Users: %s]", t.Name, userStr)
				if suffix := manualSuffix(t); suffix != "" {
					line += " " + suffix
				}
				fmt.Println(line)
			}
			fmt.Println("Connect using: ssh <target-name> or ssh <user>@<target-name>")
			return nil
		},
	}
}

func printTargetsJSON(s *state.State) error {
	workspaces := make(map[string]string, len(s.Workspaces))
	for _, w := range s.Workspaces {
		workspaces[w.ID] = w.Name
	}

	type target struct {
		Name       string   `json:"name"`
		Workspace  string   `json:"workspace"`
		Users      []string `json:"users"`
		Manual     bool     `json:"manual"`
		LastSynced string   `json:"last_synced,omitempty"`
	}
	out := struct {
		Targets []target `json:"targets"`
	}{Targets: make([]target, 0, len(s.Targets))}

	for _, t := range s.Targets {
		tgt := target{
			Name:      t.Name,
			Workspace: workspaces[t.WorkspaceID],
			Users:     t.Usernames,
		}
		if t.DaemonID == "" {
			tgt.Manual = true
			tgt.LastSynced = t.Metadata["last_manual_sync"]
		}
		out.Targets = append(out.Targets, tgt)
	}
	return printJSON(out)
}
