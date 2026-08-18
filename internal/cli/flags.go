// Package cli defines the nk command tree and its flags. The root command
// is assembled in Root.
package cli

import (
	"github.com/urfave/cli/v3"
)

// Flags returns the global flags shared by every command. Persistent
// settings are resolved in state.FromCommand: flags and environment
// variables override the values in config.json.
func Flags() []cli.Flag {
	return []cli.Flag{
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
	}
}
