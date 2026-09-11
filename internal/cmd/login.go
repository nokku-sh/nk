package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
)

func loginCMD() *cli.Command {
	return &cli.Command{
		Name:    "login",
		Usage:   "Authenticate or refresh credentials",
		Aliases: []string{"refresh"},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			s := state.FromCommand(cmd)
			c, err := client.New(s)
			if err != nil {
				return err
			}
			if err = c.Sync(ctx, true); err != nil {
				return err
			}
			c.PrewarmCerts(ctx)
			fmt.Println("Signed in and synced")
			return nil
		},
	}
}

func logoutCMD() *cli.Command {
	return &cli.Command{
		Name:  "logout",
		Usage: "Logout and remove local credentials and cached state",
		Action: func(_ context.Context, _ *cli.Command) error {
			if err := paths.RemoveConfigDir(); err != nil {
				return err
			}
			if err := paths.RemoveSSHConfigInclude(); err != nil {
				return err
			}
			fmt.Println("Logged out. Removed credentials, certificates, and cached state")
			return nil
		},
	}
}
