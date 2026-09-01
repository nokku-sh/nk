// Package cmd defines the nk command tree. Each command resolves its state
// through state.FromCommand and performs network I/O only when the command
// needs fresh data; access is synced just in time and falls back to the
// cached snapshot whenever the backend is unreachable.
package cmd

import (
	"github.com/urfave/cli/v3"
)

const (
	jsonFlag    = "json"
	jsonFlagUse = "Output machine-readable JSON"
)

// Commands is the full command tree wired into the root command.
var Commands = []*cli.Command{
	loginCMD(),
	logoutCMD(),
	proxyCMD(),
	listCMD(),
	doctorCMD(),
	pkiCMD(),
}
