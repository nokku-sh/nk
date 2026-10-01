// Package cmd defines the nk command tree.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/ui"
)

var jsonFlag = &cli.BoolFlag{Name: "json", Usage: "Output machine-readable JSON"}

// Commands is the full command tree wired into the root command.
var Commands = []*cli.Command{
	loginCMD(),
	logoutCMD(),
	listCMD(),
	syncCMD(),
	targetCMD(),
	pkiCMD(),
	doctorCMD(),
	proxyCMD(),
	prepareCMD(),
	agentCMD(),
}

// connect syncs access just in time, signing in through the browser when
// needed, and falls back to the cached snapshot when the backend is
// unreachable.
func connect(ctx context.Context, cmd *cli.Command) (*client.Client, error) {
	s, err := state.FromCommand(cmd)
	if err != nil {
		return nil, err
	}
	c, err := client.New(s)
	if err != nil {
		return nil, err
	}
	if err = c.SyncOrCache(ctx, true); err != nil {
		return nil, err
	}
	return c, nil
}

// warnf prints a highlighted warning to stderr.
func warnf(format string, args ...any) {
	fmt.Fprintln(os.Stderr, ui.Yellow("warning: "+fmt.Sprintf(format, args...)))
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
