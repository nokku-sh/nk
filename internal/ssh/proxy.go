// Package ssh manages the SSH identity, certificates, and proxy plumbing for nk.
package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/nokku-sh/nk/internal/state"
)

// RelayDialer opens a relayed connection to the target through the nokku
// backend, for when the target's endpoints are unreachable.
type RelayDialer func(ctx context.Context, target *state.Target) (io.ReadWriteCloser, error)

// halfCloseWriter lets proxyIO signal end-of-stdin without ending the
// connection. Implemented by TCP connections and the relay stream.
type halfCloseWriter interface{ CloseWrite() error }

// Proxy pipes an ssh ProxyCommand connection to the target. Direct
// endpoints are tried first. When every dial fails, the connection falls
// back to the relay. relay may be nil.
func Proxy(ctx context.Context, target *state.Target, port string, relay RelayDialer) error {
	if target == nil {
		return fmt.Errorf("internal error: nil target")
	}

	// Shuffle to avoid hotspotting
	endpoints := make([]string, len(target.Endpoints))
	copy(endpoints, target.Endpoints)
	//nolint:gosec // no need for crypto
	rand.Shuffle(len(endpoints), func(i, j int) {
		endpoints[i], endpoints[j] = endpoints[j], endpoints[i]
	})

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	var dialErrs []error
	for _, ep := range endpoints {
		addr, err := normalizeEndpoint(ep, port)
		if err != nil {
			dialErrs = append(dialErrs, fmt.Errorf("invalid endpoint %q: %w", ep, err))
			continue
		}

		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			dialErrs = append(dialErrs, fmt.Errorf("failed to dial %s: %w", addr, err))
			continue
		}
		return proxyIO(ctx, conn)
	}

	if len(dialErrs) > 0 {
		return useRelay(ctx, target, relay, fmt.Errorf("all endpoints failed:\n%w", errors.Join(dialErrs...)))
	}
	return useRelay(ctx, target, relay)
}

// ProxyRelay pipes the connection through the relay unconditionally,
// skipping the direct dial entirely.
func ProxyRelay(ctx context.Context, target *state.Target, relay RelayDialer) error {
	if target == nil {
		return fmt.Errorf("internal error: nil target")
	}
	if relay == nil {
		return errors.New("relay is not available")
	}
	rc, err := relay(ctx, target)
	if err != nil {
		return fmt.Errorf("relay connection failed: %w", err)
	}
	return proxyIO(ctx, rc)
}

func useRelay(ctx context.Context, target *state.Target, relay RelayDialer, directErrs ...error) error {
	if relay == nil {
		if len(directErrs) > 0 {
			return directErrs[0]
		}
		return fmt.Errorf("target %s has no endpoints configured", target.Name)
	}
	if len(directErrs) > 0 {
		slog.Info("direct connection failed, using relay", "target", target.Name)
	} else {
		slog.Info("no direct endpoints, using relay", "target", target.Name)
	}
	rc, err := relay(ctx, target)
	if err != nil {
		return fmt.Errorf("relay connection failed: %w", err)
	}
	return proxyIO(ctx, rc)
}

func proxyIO(ctx context.Context, conn io.ReadWriteCloser) error {
	defer func() { _ = conn.Close() }()

	// Closing the connection is the only way to unblock the io.Copy calls
	// when the context is cancelled: they read from stdin/stdout pipes.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	var eg errgroup.Group

	eg.Go(func() error {
		_, err := io.Copy(os.Stdout, conn)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return nil
	})

	eg.Go(func() error {
		_, err := io.Copy(conn, os.Stdin)
		if hc, ok := conn.(halfCloseWriter); ok {
			_ = hc.CloseWrite()
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return nil
	})

	return eg.Wait()
}

// ResolveTarget resolves an ssh host argument to a single target. A host is a
// bare target name, or "workspace/target" to disambiguate duplicates. The
// workspace part may be either a workspace name or ID.
func ResolveTarget(s *state.State, host string) (*state.Target, error) {
	name, workspace := host, ""
	if before, after, found := strings.Cut(host, "/"); found {
		workspace, name = before, after
	}

	targets := s.TargetsByName(name)
	if workspace != "" {
		for _, t := range targets {
			if t.WorkspaceID == workspace {
				return t, nil
			}
		}
		for _, t := range targets {
			for _, ws := range s.Workspaces {
				if ws.Name == workspace && ws.ID == t.WorkspaceID {
					return t, nil
				}
			}
		}
		return nil, fmt.Errorf("target %q not found in workspace %q", name, workspace)
	}

	switch len(targets) {
	case 0:
		return nil, fmt.Errorf("target %q not found in your allowed targets", name)
	case 1:
		return targets[0], nil
	default:
		return nil, fmt.Errorf(
			"target %q is ambiguous across %d workspaces; use <workspace>/<target>",
			name,
			len(targets),
		)
	}
}

func normalizeEndpoint(endpoint, sshPort string) (string, error) {
	if endpoint == "" {
		return "", errors.New("empty endpoint")
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err == nil {
		if port == "" {
			port = sshPort
		}
		return net.JoinHostPort(host, port), nil
	}

	return net.JoinHostPort(endpoint, sshPort), nil
}
