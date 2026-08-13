package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"

	"github.com/nokku-sh/nk/internal/tpm"
	"github.com/nokku-sh/nk/internal/util"
)

// ServeAgent serves the TPM identity key over an SSH agent socket so
// ssh can sign with it. No-op for software keys or when another live
// agent already holds the socket. The returned func stops the agent.
func ServeAgent(ctx context.Context) (func() error, error) {
	noop := func() error { return nil }
	if !TPMKeyActive() {
		return noop, nil
	}

	ln, alreadyServing, err := listenAgentSocket(ctx)
	if err != nil {
		return nil, err
	}
	if alreadyServing {
		return noop, nil
	}

	key, err := tpm.OpenKey(sshTPMSalt)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("open TPM key: %w", err)
	}

	ring := agent.NewKeyring()
	if err = ring.Add(agent.AddedKey{PrivateKey: key, Comment: "nokku (tpm)"}); err != nil {
		_ = ln.Close()
		_ = key.Close()
		return nil, fmt.Errorf("add TPM key to agent: %w", err)
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
		_ = os.Remove(util.AgentSocket())
		return key.Close()
	}, nil
}

// listenAgentSocket binds the agent socket, alreadyServing is true when a
// live agent holds the socket, a stale socket file is removed and rebound.
func listenAgentSocket(ctx context.Context) (ln net.Listener, alreadyServing bool, err error) {
	path := util.AgentSocket()
	var lc net.ListenConfig
	ln, err = lc.Listen(ctx, "unix", path)
	if err == nil {
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
	return ln, false, nil
}
