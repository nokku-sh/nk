package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/ssh"
)

// proxyCMD is the ProxyCommand in the generated ssh_config. ssh runs it, users
// do not.
func proxyCMD() *cli.Command {
	return &cli.Command{
		Name:      "proxy",
		Usage:     "Proxy an SSH connection (used by ssh)",
		ArgsUsage: "<target-id> <port>",
		Hidden:    true,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "relay", Usage: "Always go through the Nokku relay"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			id, port := cmd.Args().Get(0), cmd.Args().Get(1)
			if id == "" || port == "" {
				return errors.New("usage: nk proxy <target-id> <port>")
			}

			// Never open a browser under ssh, a stale session uses the cache.
			c, err := connect(ctx, cmd, false)
			if err != nil {
				return err
			}
			target := c.State.TargetByID(id)
			if target == nil {
				return errors.New("you no longer have access to this server, run nk ls to see yours")
			}
			ca := c.State.CAByID(target.CAID)
			if ca == nil {
				return fmt.Errorf("the certificate authority of %s is missing, run nk login", target.Name)
			}

			if err = c.EnsureCert(ctx, *ca, false); err != nil {
				if !ssh.CertValid(*ca, 0) {
					return fmt.Errorf("no valid certificate for %s, run nk login: %w", target.Name, err)
				}
				slog.Warn("certificate renewal failed, using the cached one", "target", target.Name, "err", err)
			}
			if err = ssh.EnsureAgent(ctx); err != nil {
				return err
			}
			return ssh.Proxy(ctx, target, port, c.Relay, cmd.Bool("relay"))
		},
	}
}

func agentCMD() *cli.Command {
	return &cli.Command{
		Name:   "agent",
		Usage:  "Serve the machine SSH identity (started by nk proxy)",
		Hidden: true,
		Action: func(ctx context.Context, _ *cli.Command) error {
			return ssh.RunAgent(ctx)
		},
	}
}
