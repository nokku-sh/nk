package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/api"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/util"
)

const (
	jsonFlag    = "json"
	jsonFlagUse = "Output machine-readable JSON"
)

// Commands returns every subcommand of the nk CLI.
func Commands() []*cli.Command {
	return []*cli.Command{
		proxyCommand(),
		doctorCommand(),
		listCommand(),
		pkiCommand(),
		loginCommand(),
		logoutCommand(),
	}
}

func proxyCommand() *cli.Command {
	return &cli.Command{
		Name:      "proxy",
		Usage:     "Proxy an SSH connection (internal use by SSH)",
		ArgsUsage: "[host] [port]",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			host := cmd.Args().Get(0)
			if host == "" {
				return fmt.Errorf("host name is required")
			}
			port := cmd.Args().Get(1)
			if port == "" {
				port = "22"
			}

			// The proxy path is deliberately lightweight: it loads cached
			// state (no sync), resolves the target, and only signs a
			// certificate when it is missing or close to expiry.
			s := state.FromCommand(cmd)
			client, err := api.New(s, cmd.Bool("require-tpm"))
			if err != nil {
				return err
			}

			target, err := ssh.ResolveTarget(s, host)
			if err != nil {
				return err
			}
			if err = client.SignTarget(ctx, target); err != nil {
				if !ssh.CertificateOnDisk(target.CAID) {
					return err
				}
				slog.Warn("certificate signing failed, using cached certificate",
					"target", target.Name, "err", err)
			}

			// Serve the TPM key over the agent socket before ssh starts the
			// authentication phase.
			stopAgent, err := ssh.ServeAgent(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = stopAgent() }()

			return ssh.Proxy(ctx, target, port)
		},
	}
}

func doctorCommand() *cli.Command {
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
			report := runDoctor(
				ctx,
				state.FromCommand(cmd),
				cmd.Bool("require-tpm"),
				cmd.Bool("fix"),
			)
			_ = printReport(os.Stdout, report, cmd.Bool(jsonFlag))
			if code := report.ExitCode(); code != 0 {
				return cli.Exit("", code)
			}
			return nil
		},
	}
}

func listCommand() *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"ls"},
		Usage:   "List available machines across all workspaces",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: jsonFlag, Usage: jsonFlagUse},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			client, err := api.Connect(ctx, cmd)
			if err != nil {
				return err
			}

			s := client.State
			if cmd.Bool(jsonFlag) {
				return printTargetsJSON(s)
			}
			if len(s.Targets) == 0 {
				fmt.Println("No targets available.")
				return nil
			}

			fmt.Printf("Targets (%d):\n", len(s.Targets))
			for _, t := range s.Targets {
				users := targetUsers(t)
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

func loginCommand() *cli.Command {
	return &cli.Command{
		Name:    "login",
		Usage:   "Authenticate or refresh credentials",
		Aliases: []string{"refresh"},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			_, err := api.Connect(ctx, cmd)
			return err
		},
	}
}

func logoutCommand() *cli.Command {
	return &cli.Command{
		Name:  "logout",
		Usage: "Logout and remove credentials",
		Action: func(_ context.Context, _ *cli.Command) error {
			state.New().Clear()
			util.CleanupPaths()
			fmt.Println("Cleaned up credentials")
			return nil
		},
	}
}
