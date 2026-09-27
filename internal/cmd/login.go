package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/ui"
)

func loginCMD() *cli.Command {
	return &cli.Command{
		Name:    "login",
		Usage:   "Sign in and set up ssh for your servers",
		Aliases: []string{"refresh"},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			s, err := state.FromCommand(cmd)
			if err != nil {
				return err
			}
			c, err := client.New(s)
			if err != nil {
				return err
			}
			if err = c.Sync(ctx, true); err != nil {
				return err
			}
			c.PrewarmCerts(ctx)

			who := "service account"
			if s.User != nil {
				who = s.User.Email
			}
			fmt.Printf("%s Signed in as %s, %d servers available\n", ui.Green("✔"), who, len(s.Targets))
			fmt.Println("  List them with nk ls, connect with ssh <server>")
			return nil
		},
	}
}

func logoutCMD() *cli.Command {
	return &cli.Command{
		Name:  "logout",
		Usage: "Sign out and remove local credentials, certificates, and cached state",
		Action: func(context.Context, *cli.Command) error {
			if err := ssh.RemoveInclude(); err != nil {
				return err
			}
			if err := paths.RemoveConfigDir(); err != nil {
				return err
			}
			fmt.Println("Signed out. Removed credentials, certificates, and cached state")
			return nil
		},
	}
}
