package state

import "github.com/urfave/cli/v3"

// FromCommand resolves the session state for a command: it loads the
// persisted config and cache, then overlays any explicitly set flags or
// environment variables. The service-account token is kept ephemeral and
// is never written to disk.
//
// This is the single place where CLI inputs become state; every command
// resolves its state through here so flag handling stays consistent.
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

	// Fall back to the flag default when nothing was persisted.
	if s.APIURL == "" {
		s.APIURL = cmd.String("api")
	}

	return s
}
