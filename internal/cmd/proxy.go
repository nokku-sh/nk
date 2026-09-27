package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
)

// proxyFreshFor is how long nk proxy trusts the cached access snapshot.
const proxyFreshFor = time.Minute

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
			s, err := state.FromCommand(cmd)
			if err != nil {
				return err
			}
			// Built on first use, so a fresh snapshot with a valid cert never
			// touches the TPM or the backend.
			backend := sync.OnceValues(func() (*client.Client, error) { return client.New(s) })

			// The daemon enforces revocation itself, so a young snapshot only
			// delays new grants, and fan-out over many hosts syncs once.
			if time.Since(s.SyncedAt) > proxyFreshFor || s.TargetByID(id) == nil {
				c, cerr := backend()
				if cerr != nil {
					return cerr
				}
				// Never open a browser under ssh, a stale session uses the cache.
				if err = c.SyncOrCache(ctx, false); err != nil {
					return err
				}
			}
			target := s.TargetByID(id)
			if target == nil {
				return errors.New("you no longer have access to this server, run nk ls to see yours")
			}
			ca := s.CAByID(target.CAID)
			if ca == nil {
				return fmt.Errorf("the certificate authority of %s is missing, run nk login", target.Name)
			}

			if !ssh.CertValid(*ca, client.CertRenewWindow) {
				c, cerr := backend()
				if cerr == nil {
					cerr = c.EnsureCert(ctx, *ca, false)
				}
				if cerr != nil {
					if !ssh.CertValid(*ca, 0) {
						return fmt.Errorf("no valid certificate for %s, run nk login: %w", target.Name, cerr)
					}
					slog.Warn("certificate renewal failed, using the cached one", "target", target.Name, "err", cerr)
				}
			}
			if err = ssh.EnsureAgent(ctx); err != nil {
				return err
			}
			relay := func(ctx context.Context, t *state.Target) (io.ReadWriteCloser, error) {
				c, cerr := backend()
				if cerr != nil {
					return nil, cerr
				}
				return c.Relay(ctx, t)
			}
			return ssh.Proxy(ctx, target, port, relay, cmd.Bool("relay"))
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
