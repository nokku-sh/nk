package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
)

func proxyCMD() *cli.Command {
	return &cli.Command{
		Name:      "proxy",
		Usage:     "Proxy an SSH connection (internal use by SSH)",
		ArgsUsage: "[host] [port]",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			host := cmd.Args().Get(0)
			if host == "" {
				return fmt.Errorf("host name is required")
			}
			port := cmd.Args().Get(1)
			if port == "" {
				port = "22"
			}

			// Access is synced just in time: permissions may have changed
			// since the last login. The sync is non-interactive and fails
			// fast (5s bound); when it fails, the cached snapshot keeps the
			// connection working offline. A missing or expired session never
			// triggers a browser flow here; the user runs nk login instead.
			s := state.FromCommand(cmd)
			client, err := client.New(s)
			if err != nil {
				return err
			}
			err = client.SyncOrCache(ctx, false)
			if err != nil {
				return err
			}

			target, err := ssh.ResolveTarget(s, host)
			if err != nil {
				return err
			}

			// Sign only this target's certificate, and only when it is
			// missing or close to expiry. With a stale or missing session
			// this fails fast; a cached certificate on disk is still used.
			if err = client.EnsureTargetCert(ctx, target, false); err != nil {
				if !ssh.CertificateOnDisk(target.CAID) {
					return err
				}
				slog.Warn("certificate signing failed, using cached certificate",
					"target", target.Name, "err", err)
			}

			// Serve the TPM key over the agent socket before ssh starts the
			// authentication phase.
			stopAgent, err := ssh.ServeAgent(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = stopAgent() }()

			return ssh.Proxy(ctx, target, port)
		},
	}
}
