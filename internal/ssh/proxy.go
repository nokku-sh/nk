// Package ssh manages the SSH identity, certificates, and proxy plumbing for nk.
package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/nokku-sh/nk/internal/state"
)

// Proxy handles native ssh ProxyCommand connections.
func Proxy(ctx context.Context, target *state.Target, port string) error {
	if target == nil {
		return fmt.Errorf("internal error: nil target")
	}
	if len(target.Endpoints) == 0 {
		return fmt.Errorf("target %s has no endpoints configured", target.Name)
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

	// If we get here, all endpoints failed. Return a combined error.
	return fmt.Errorf("all endpoints failed:\n%w", errors.Join(dialErrs...))
}

func proxyIO(ctx context.Context, conn net.Conn) error {
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
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
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

	targets := s.GetTargetsByName(name)
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

	// If endpoint already contains port
	host, port, err := net.SplitHostPort(endpoint)
	if err == nil {
		if port == "" {
			port = sshPort
		}
		return net.JoinHostPort(host, port), nil
	}

	// No port, treat whole string as host
	return net.JoinHostPort(endpoint, sshPort), nil
}
