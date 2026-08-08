// Package ssh provides various ssh utility functions for the application.
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
func Proxy(ctx context.Context, s *state.State, host, port string) error {
	targetName, workspaceName := parseHost(host)
	targets := resolveTargets(s, targetName, workspaceName)
	if len(targets) == 0 {
		return fmt.Errorf("target %s not found in your allowed targets", host)
	}
	target := targets[0]

	if len(target.Endpoints) == 0 {
		return fmt.Errorf("target %s has no endpoints configured", host)
	}

	// Shuffle to avoid hotspotting
	endpoints := make([]string, len(target.Endpoints))
	copy(endpoints, target.Endpoints)
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
			if len(endpoints) > 1 {
				fmt.Printf("Skipping %s: %v", addr, err)
			}
			continue
		}
		return proxyIO(conn)
	}

	// If we get here, all endpoints failed. Return a combined error.
	return fmt.Errorf("all endpoints failed:\n%w", errors.Join(dialErrs...))
}

func proxyIO(conn net.Conn) error {
	defer func() { _ = conn.Close() }()

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

func parseHost(host string) (targetName, workspaceName string) {
	if before, after, found := strings.Cut(host, "/"); found {
		return after, before
	}
	return host, ""
}

func resolveTargets(s *state.State, targetName, workspaceName string) []*state.Target {
	targets := s.GetTargetsByName(targetName)
	if workspaceName != "" {
		var filtered []*state.Target
		for _, t := range targets {
			if t.WorkspaceID == workspaceName {
				filtered = append(filtered, t)
				continue
			}
			for _, ws := range s.Workspaces {
				if ws.Name == workspaceName && ws.ID == t.WorkspaceID {
					filtered = append(filtered, t)
					break
				}
			}
		}
		if len(filtered) > 0 {
			return filtered
		}
	}
	if len(targets) > 1 {
		fmt.Printf(
			"Target name %q is ambiguous across workspaces (%d matches)",
			targetName,
			len(targets),
		)
	}
	return targets
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
