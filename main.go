package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/urfave/cli/v3"

	nkcli "github.com/nokku-sh/nk/internal/cli"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/util"
)

func main() {
	cmd := &cli.Command{
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
			s := state.New()
			s.APIURL = cmd.String("api")
			s.KeyType = cmd.String("key-type")
			if cmd.IsSet("token") {
				s.Token = cmd.String("token")
			}
			return s.Save()
		},
		Commands: nkcli.Commands(),
		Flags:    nkcli.Flags(),
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "nk: %v\n", err)
		os.Exit(1)
	}
}
