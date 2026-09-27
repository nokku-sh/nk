// Package ssh manages the SSH identity, certificates, and proxy plumbing for nk.
package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/nokku-sh/nk/internal/state"
)

// RelayDialer opens a relayed connection to a daemon target through the
// backend.
type RelayDialer func(ctx context.Context, target *state.Target) (io.ReadWriteCloser, error)

// Proxy pipes an ssh ProxyCommand connection to the target. Endpoints are
// tried in order, a daemon target falls back to the relay. forceRelay skips
// the direct dials.
func Proxy(ctx context.Context, target *state.Target, port string, relay RelayDialer, forceRelay bool) error {
	if forceRelay && target.Manual() {
		return fmt.Errorf("%s has no daemon, so it cannot be reached through the relay", target.Name)
	}

	var errs []error
	if !forceRelay {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		for _, ep := range target.Endpoints {
			conn, err := dialer.DialContext(ctx, "tcp", endpointAddr(ep, port))
			if err == nil {
				return pipe(ctx, conn)
			}
			errs = append(errs, err)
		}
	}

	if target.Manual() {
		if len(errs) == 0 {
			return fmt.Errorf("%s has no address, run nk sync on it again", target.Name)
		}
		return fmt.Errorf("cannot reach %s: %w", target.Name, errors.Join(errs...))
	}
	if len(errs) > 0 {
		slog.Info("direct connection failed, using relay", "target", target.Name)
	}
	rc, err := relay(ctx, target)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", target.Name, errors.Join(append(errs, err)...))
	}
	return pipe(ctx, rc)
}

// endpointAddr keeps an endpoint's own port and uses port otherwise.
func endpointAddr(endpoint, port string) string {
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		return endpoint
	}
	return net.JoinHostPort(endpoint, port)
}

func pipe(ctx context.Context, conn io.ReadWriteCloser) error {
	defer func() { _ = conn.Close() }()
	// Closing is the only way to unblock the copies on cancel.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	var eg errgroup.Group
	eg.Go(func() error {
		_, err := io.Copy(os.Stdout, conn)
		return err
	})
	eg.Go(func() error {
		_, err := io.Copy(conn, os.Stdin)
		// Half-close so sshd sees EOF but can keep sending.
		if hc, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
		return err
	})
	return eg.Wait()
}
