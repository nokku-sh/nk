package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"

	"github.com/nokku-sh/mon/tpm"

	"github.com/nokku-sh/nk/internal/paths"
)

// ServeAgent serves the machine SSH identity on a local agent socket so ssh can
// sign with it. A software key is unwrapped only inside this process. It is a
// no-op when no identity exists or another live agent holds the socket. The
// returned func stops the agent.
func ServeAgent(ctx context.Context) (func() error, error) {
	noop := func() error { return nil }

	if IdentityMethod() == "" {
		return noop, nil
	}
	signer, err := newSSHSigner(false)
	if err != nil {
		return nil, err
	}
	label := "nokku (software)"
	if signer.Method() == tpm.MethodTPM {
		label = "nokku (tpm)"
	}

	ln, alreadyServing, err := listenAgentSocket(ctx)
	if err != nil {
		_ = signer.Close()
		return nil, err
	}
	if alreadyServing {
		_ = signer.Close()
		return noop, nil
	}

	ring := agent.NewKeyring()
	if err = ring.Add(agent.AddedKey{PrivateKey: signer, Comment: label}); err != nil {
		_ = ln.Close()
		_ = signer.Close()
		return nil, fmt.Errorf("add identity to agent: %w", err)
	}

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return // listener closed
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = agent.ServeAgent(ring, conn)
			}()
		}
	}()

	return func() error {
		_ = ln.Close()
		_ = os.Remove(paths.AgentSocket())
		return signer.Close()
	}, nil
}

// listenAgentSocket binds the agent socket. alreadyServing is true when a live
// agent already holds it. A stale socket file is removed and rebound.
func listenAgentSocket(ctx context.Context) (ln net.Listener, alreadyServing bool, err error) {
	path := paths.AgentSocket()
	var lc net.ListenConfig
	ln, err = lc.Listen(ctx, "unix", path)
	if err == nil {
		if err = secureAgentSocket(path); err != nil {
			_ = ln.Close()
			return nil, false, err
		}
		return ln, false, nil
	}
	var d net.Dialer
	if conn, dialErr := d.DialContext(ctx, "unix", path); dialErr == nil {
		_ = conn.Close()
		return nil, true, nil
	}
	if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("remove stale agent socket: %w", err)
	}
	ln, err = lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, false, fmt.Errorf("bind agent socket: %w", err)
	}
	if err = secureAgentSocket(path); err != nil {
		_ = ln.Close()
		return nil, false, err
	}
	return ln, false, nil
}

// secureAgentSocket limits the socket to the owning user, since the parent
// directory mode alone is not enough.
func secureAgentSocket(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure agent socket: %w", err)
	}
	return nil
}
