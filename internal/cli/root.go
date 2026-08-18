package cli

import (
	"context"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/util"
)

// Root returns the root command with its global flags and hooks. Running nk
// without a subcommand persists the resolved configuration.
func Root() *cli.Command {
	return &cli.Command{
		EnableShellCompletion: true,
		Suggest:               true,
		Name:                  "nk",
		Usage:                 "secure access, simplified",
		Version:               buildinfo.String(),
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			logx.Init(cmd.Bool("debug"))
			if err := util.VerifyPaths(); err != nil {
				return nil, err
			}
			return ctx, nil
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			return state.FromCommand(cmd).Save()
		},
		Commands: Commands(),
		Flags:    Flags(),
	}
}
