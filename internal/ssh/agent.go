package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/nokku-sh/mon/tpm"

	"github.com/nokku-sh/nk/internal/paths"
)

// agentIdle is how long the background agent lives without a connection.
const agentIdle = 30 * time.Minute

// EnsureAgent makes sure a background nk agent serves the SSH identity on
// paths.AgentSocket. One shared agent outlives every ssh session, so parallel
// sessions never lose their signer when another one ends.
func EnsureAgent(ctx context.Context) error {
	if agentAlive(ctx) {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	//nolint:noctx // the agent must outlive this ssh session
	cmd := exec.Command(exe, "agent")
	detach(cmd)
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("start nk agent: %w", err)
	}
	_ = cmd.Process.Release()

	for range 50 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if agentAlive(ctx) {
			return nil
		}
	}
	return errors.New("the nk agent did not start, run nk doctor")
}

// RunAgent serves the SSH identity until ctx ends or the agent sits idle. It
// returns at once when another agent already serves the socket.
func RunAgent(ctx context.Context) error {
	if agentAlive(ctx) {
		return nil
	}
	ln, err := listenAgent(ctx)
	if err != nil {
		if agentAlive(ctx) {
			return nil // lost a start race to another agent
		}
		return fmt.Errorf("listen on agent socket: %w", err)
	}
	idle := time.AfterFunc(agentIdle, func() { _ = ln.Close() })
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	var id identity
	for {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return nil
		}
		idle.Reset(agentIdle)
		ring, keyErr := id.keyring()
		if keyErr != nil {
			slog.Error("load ssh identity", "err", keyErr)
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { _ = conn.Close() }()
			_ = agent.ServeAgent(ring, conn)
		}()
	}
}

// identity reloads the signer whenever nk wrote a new public key, so a
// recreated identity never needs an agent restart.
type identity struct {
	pub  []byte
	ring agent.Agent
}

func (id *identity) keyring() (agent.Agent, error) {
	pub, err := os.ReadFile(paths.PubKeyFile())
	if err != nil {
		return nil, err
	}
	if id.ring != nil && bytes.Equal(pub, id.pub) {
		return id.ring, nil
	}
	// A replaced signer is not closed, connections may still be using it.
	signer, err := newSSHSigner(false)
	if err != nil {
		return nil, err
	}
	comment := "nokku (software)"
	if signer.Method() == tpm.MethodTPM {
		comment = "nokku (tpm)"
	}
	ring := agent.NewKeyring()
	if err = ring.Add(agent.AddedKey{PrivateKey: signer, Comment: comment}); err != nil {
		return nil, err
	}
	id.pub, id.ring = pub, ring
	return ring, nil
}

func agentAlive(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := dialAgent(ctx)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
