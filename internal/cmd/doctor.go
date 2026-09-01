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
		Usage: "Check local system setup and configuration",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: jsonFlag, Usage: jsonFlagUse},
			&cli.BoolFlag{
				Name:  "fix",
				Usage: "Repair common issues (ssh config, permissions)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			report := doctor.RunDoctor(
				ctx,
				state.FromCommand(cmd),
				cmd.Bool("fix"),
			)
			if err := doctor.PrintReport(os.Stdout, report, cmd.Bool(jsonFlag)); err != nil {
				return err
			}
			if code := report.ExitCode(); code != 0 {
				return cli.Exit("", code)
			}
			return nil
		},
	}
}
