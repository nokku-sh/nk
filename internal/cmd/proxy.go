package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/ssh"
)

func proxyCMD() *cli.Command {
	return &cli.Command{
		Name:      "proxy",
		Usage:     "Proxy an SSH connection (internal use by SSH)",
		ArgsUsage: "[host] [port]",
		Hidden:    true,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "relay",
				Usage: "route the connection through the nokku relay, skipping direct connection",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			host := cmd.Args().Get(0)
			if host == "" {
				return fmt.Errorf("host name is required")
			}
			port := cmd.Args().Get(1)
			if port == "" {
				port = "22"
			}

			// A missing session never opens a browser, the user runs nk login.
			c, s, err := connect(ctx, cmd, false)
			if err != nil {
				return err
			}

			target, err := ssh.ResolveTarget(s, host)
			if err != nil {
				return err
			}

			// Keep using the cached certificate when signing fails offline.
			if err = c.EnsureTargetCert(ctx, target, false); err != nil {
				if !ssh.CertificateOnDisk(target.CAID) {
					return err
				}
				slog.Warn("certificate signing failed, using cached certificate",
					"target", target.Name, "err", err)
			}

			// Serve the machine identity before ssh starts authenticating.
			stopAgent, err := ssh.ServeAgent(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = stopAgent() }()

			// Direct endpoints first with the relay as fallback. --relay forces it.
			relay := ssh.RelayDialer(c.Relay)
			if cmd.Bool("relay") {
				return ssh.ProxyRelay(ctx, target, relay)
			}
			return ssh.Proxy(ctx, target, port, relay)
		},
	}
}
