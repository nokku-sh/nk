// Package cmd defines the nk command tree.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	"github.com/nokku-sh/nk/internal/state"
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
	syncCMD(),
	targetCMD(),
	doctorCMD(),
	pkiCMD(),
}

// connect syncs access just in time and falls back to the cached snapshot when
// the backend is unreachable. When interactive is false a missing session is an
// error instead of a login flow.
func connect(ctx context.Context, cmd *cli.Command, interactive bool) (*client.Client, *state.State, error) {
	s := state.FromCommand(cmd)
	c, err := client.New(s)
	if err != nil {
		return nil, nil, err
	}
	if err = c.SyncOrCache(ctx, interactive); err != nil {
		return nil, nil, err
	}
	return c, s, nil
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
