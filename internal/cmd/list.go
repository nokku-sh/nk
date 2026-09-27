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

func listCMD() *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"ls"},
		Usage:   "List the servers you can connect to",
		Flags:   []cli.Flag{jsonFlag},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			c, err := connect(ctx, cmd)
			if err != nil {
				return err
			}
			s := c.State
			if cmd.Bool(jsonFlag.Name) {
				return printTargetsJSON(s)
			}
			if len(s.Targets) == 0 {
				fmt.Println("You have no servers yet. Ask an admin for access.")
				return nil
			}

			for _, t := range s.Targets {
				users := ui.Dim("no accounts")
				if len(t.Usernames) > 0 {
					users = strings.Join(t.Usernames, ", ")
				}
				fmt.Printf("  %-24s %s %s\n", t.Name, users, ui.Dim(manualNote(t)))
			}
			fmt.Println("\nConnect with: ssh <server> or ssh <user>@<server>")
			return nil
		},
	}
}

// manualNote shows how fresh a daemonless target's access is.
func manualNote(t state.Target) string {
	if !t.Manual() {
		return ""
	}
	last := t.LastManualSync()
	if last.IsZero() {
		return "(manual, never synced)"
	}
	return "(manual, synced " + ui.HumanizeDuration(time.Since(last)) + " ago)"
}

func printTargetsJSON(s *state.State) error {
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
		out.Targets = append(out.Targets, target{
			Name:       t.Name,
			Workspace:  s.WorkspaceName(t.WorkspaceID),
			Users:      t.Usernames,
			Manual:     t.Manual(),
			LastSynced: t.Metadata["last_manual_sync"],
		})
	}
	return printJSON(out)
}
