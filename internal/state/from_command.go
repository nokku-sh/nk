package state

import "github.com/urfave/cli/v3"

// FromCommand builds session state from persisted config and cache, then overlays set flags.
func FromCommand(cmd *cli.Command) *State {
	s := New()

	if cmd.IsSet("api") {
		s.APIURL = cmd.String("api")
	}
	if cmd.IsSet("ttl") {
		s.TTL = cmd.Duration("ttl")
	}
	if cmd.IsSet("insecure") {
		s.Insecure = cmd.Bool("insecure")
	}
	if cmd.IsSet("token") {
		s.Token = cmd.String("token")
	}
	s.RequireTPM = cmd.Bool("require-tpm")

	if s.APIURL == "" {
		s.APIURL = cmd.String("api")
	}

	return s
}
