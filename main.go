package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/cmd"
	"github.com/nokku-sh/nk/internal/paths"
)

func main() {
	root := &cli.Command{
		EnableShellCompletion: true,
		Suggest:               true,
		Name:                  "nk",
		Usage:                 "secure access, simplified",
		Version:               buildinfo.String(),
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			logx.Init(cmd.Bool("debug"))
			if err := paths.VerifyPaths(); err != nil {
				return nil, err
			}
			return ctx, nil
		},
		Commands: cmd.Commands,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "api",
				Usage:   "Nokku API URL",
				Value:   "https://app.nokku.sh",
				Sources: cli.EnvVars("NK_API_URL"),
			},
			&cli.StringFlag{
				Name:    "token",
				Usage:   "Service account token (skips browser login, for CI/CD)",
				Sources: cli.EnvVars("NK_TOKEN"),
			},
			&cli.DurationFlag{
				Name:    "ttl",
				Usage:   "Certificate TTL",
				Sources: cli.EnvVars("NK_TTL"),
			},
			&cli.BoolFlag{
				Name:    "require-tpm",
				Usage:   "Require a TPM 2.0 and refuse the software key fallback",
				Sources: cli.EnvVars("NK_REQUIRE_TPM"),
			},
			&cli.BoolFlag{
				Name:    "insecure",
				Usage:   "Disable TLS verification",
				Sources: cli.EnvVars("NK_INSECURE"),
			},
			&cli.BoolFlag{
				Name:    "debug",
				Usage:   "Enable debug logging",
				Sources: cli.EnvVars("NK_DEBUG"),
			},
		},
	}

	if err := root.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "nk: %v\n", err)
		os.Exit(1)
	}
}
