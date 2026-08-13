// Package cli assembles the nk command tree. main only wires up signals and
// delegates to Run, the command actions live here.
package cli

import (
	"context"
	"fmt"
	"slices"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	altsrc "github.com/urfave/cli-altsrc/v3"
	altsrcjson "github.com/urfave/cli-altsrc/v3/json"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/util"
)

// Run executes the nk command tree with the given context and arguments.
func Run(ctx context.Context, args []string) error {
	return app().Run(ctx, args)
}

// app builds the root command with all flags and subcommands.
func app() *cli.Command {
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
			s := state.New()
			s.APIURL = cmd.String("api")
			s.KeyType = cmd.String("key-type")
			if cmd.IsSet("token") {
				s.Token = cmd.String("token")
			}
			return s.Save()
		},
		Commands: commands(),
		Flags:    flags(),
	}
}

// flags returns the global flags shared by every command.
func flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "api",
			Usage: "Nokku API URL",
			Value: "https://app.nokku.sh",
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("NK_API_URL"),
				altsrcjson.JSON("api_url", altsrc.NewStringPtrSourcer(new(util.ConfigFile()))),
			),
		},
		&cli.StringFlag{
			Name:    "token",
			Usage:   "Service account token (skips browser login, for CI/CD); never stored on disk",
			Sources: cli.EnvVars("NK_TOKEN"),
		},
		&cli.StringFlag{
			Name:  "key-type",
			Usage: "SSH key algorithm (ed25519, rsa-2048, rsa-4096, ecdsa-p256, ecdsa-p384, ecdsa-p521, tpm)",
			Value: "ed25519",
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("NK_KEY_TYPE"),
				altsrcjson.JSON("key_type", altsrc.NewStringPtrSourcer(new(util.ConfigFile()))),
			),
			Action: func(_ context.Context, _ *cli.Command, val string) error {
				if !slices.Contains(ssh.ValidKeyTypes, ssh.KeyType(val)) {
					return fmt.Errorf(
						"invalid --key-type %q. Allowed choices are: %v",
						val,
						ssh.ValidKeyTypes,
					)
				}
				return nil
			},
		},
		&cli.DurationFlag{
			Name:    "ttl",
			Usage:   "Certificate TTL",
			Sources: cli.EnvVars("NK_TTL"),
		},
		&cli.BoolFlag{
			Name:    "require-tpm",
			Usage:   "Require a TPM 2.0 for request signing, refuse the software fallback key",
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
	}
}
