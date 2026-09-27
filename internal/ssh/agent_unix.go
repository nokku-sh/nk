//go:build !windows

package ssh

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/nokku-sh/nk/internal/paths"
)

func listenAgent(ctx context.Context) (net.Listener, error) {
	path := paths.AgentSocket()
	// Only called when nothing answers, so an existing file is stale.
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	// The config dir is 0700 already, this keeps the socket private if it is not.
	if err = os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

func dialAgent(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", paths.AgentSocket())
}

// detach starts the agent in its own session, so the SIGHUP ssh sends its
// ProxyCommand on exit never reaches it.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
