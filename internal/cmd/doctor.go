package cmd

import (
	"context"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/doctor"
	"github.com/nokku-sh/nk/internal/state"
)

func doctorCMD() *cli.Command {
	return &cli.Command{
		Name:  "doctor",
		Usage: "Check your setup and explain how to fix problems",
		Flags: []cli.Flag{
			jsonFlag,
			&cli.BoolFlag{Name: "fix", Usage: "Repair the ssh config, permissions, and stale certificates"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			s, err := state.FromCommand(cmd)
			if err != nil {
				return err
			}
			report := doctor.Run(ctx, s, cmd.Bool("fix"))
			if err = doctor.Print(os.Stdout, report, cmd.Bool(jsonFlag.Name)); err != nil {
				return err
			}
			if code := report.ExitCode(); code != 0 {
				return cli.Exit("doctor found issues", code)
			}
			return nil
		},
	}
}
