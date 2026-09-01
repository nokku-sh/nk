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
			client, err := client.New(ctx, s)
			if err != nil {
				return err
			}

			// login is the explicit interactive path: it may run the device
			// flow, then syncs access and prewarms certificates so the user
			// can go offline right after.
			err = client.Sync(ctx, true)
			if err != nil {
				return err
			}
			client.PrewarmCerts(ctx)
			fmt.Println("Signed in and synced")
			return nil
		},
	}
}

func logoutCMD() *cli.Command {
	return &cli.Command{
		Name:  "logout",
		Usage: "Logout and remove credentials",
		Action: func(_ context.Context, _ *cli.Command) error {
			paths.CleanupPaths()
			fmt.Println("Cleaned up credentials")
			return nil
		},
	}
}
