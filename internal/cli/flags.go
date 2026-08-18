// Package cli defines the nk command tree and its flags. The root command
// (name, version, global Before/Action hooks) is assembled in package main.
package cli

import (
	"context"
	"fmt"
	"slices"

	altsrc "github.com/urfave/cli-altsrc/v3"
	altsrcjson "github.com/urfave/cli-altsrc/v3/json"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/util"
)

// Flags returns the global flags shared by every command.
func Flags() []cli.Flag {
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
