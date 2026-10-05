// Package cmd defines the nk command tree.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/ui"
)

// saPrefix marks service-account tokens. Unlike device sessions they
// authenticate with a plain Bearer header, without DPoP binding.
const saPrefix = "nokku_sa_"

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

// loadState loads the persisted state and applies the global flags.
func loadState(cmd *cli.Command) (*state.State, error) {
	s := state.Load()
	s.Token = os.Getenv("NK_TOKEN")
	s.TTL = cmd.Duration("ttl")
	s.RequireTPM = cmd.Bool("require-tpm")
	s.Insecure = cmd.Bool("insecure")

	if s.Token != "" && !strings.HasPrefix(s.Token, saPrefix) {
		return nil, errors.New("NK_TOKEN must be a service account token starting with " + saPrefix)
	}
	if api := cmd.String("api"); s.APIURL != api && (s.APIURL == "" || cmd.IsSet("api")) {
		// Another server never gets this session or shows its targets.
		s.Config = state.Config{APIURL: api}
		s.Cache = state.Cache{}
	}
	return s, nil
}

// connect syncs access just in time, signing in through the browser when
// needed, and falls back to the cached snapshot when the backend is
// unreachable.
func connect(ctx context.Context, cmd *cli.Command) (*client.Client, error) {
	s, err := loadState(cmd)
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
