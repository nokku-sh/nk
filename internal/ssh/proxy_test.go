package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nk/internal/state"
)

func TestResolveTarget(t *testing.T) {
	t.Parallel()

	makeState := func(targets []state.Target, workspaces []state.Workspace) *state.State {
		return &state.State{Targets: targets, Workspaces: workspaces}
	}
	dupTargets := []state.Target{
		{ID: "1", Name: "db", WorkspaceID: "ws-1"},
		{ID: "2", Name: "db", WorkspaceID: "ws-2"},
	}
	dupWorkspaces := []state.Workspace{
		{ID: "ws-1", Name: "staging"},
		{ID: "ws-2", Name: "production"},
	}

	t.Run("finds a unique target by name", func(t *testing.T) {
		t.Parallel()
		s := makeState([]state.Target{{ID: "1", Name: "prod"}}, nil)
		got, err := ResolveTarget(s, "prod")
		require.NoError(t, err)
		assert.Equal(t, "1", got.ID)
	})

	t.Run("disambiguates by workspace name", func(t *testing.T) {
		t.Parallel()
		s := makeState(dupTargets, dupWorkspaces)
		got, err := ResolveTarget(s, "staging/db")
		require.NoError(t, err)
		assert.Equal(t, "1", got.ID)
	})

	t.Run("disambiguates by workspace id", func(t *testing.T) {
		t.Parallel()
		s := makeState(dupTargets, dupWorkspaces)
		got, err := ResolveTarget(s, "ws-2/db")
		require.NoError(t, err)
		assert.Equal(t, "2", got.ID)
	})

	t.Run("rejects an ambiguous bare name", func(t *testing.T) {
		t.Parallel()
		s := makeState(dupTargets, dupWorkspaces)
		_, err := ResolveTarget(s, "db")
		assert.Error(t, err, "expected ambiguity error")
	})

	t.Run("reports not found", func(t *testing.T) {
		t.Parallel()
		s := makeState(nil, nil)
		_, err := ResolveTarget(s, "missing")
		assert.Error(t, err, "expected not-found error")
	})

	t.Run("reports unknown workspace", func(t *testing.T) {
		t.Parallel()
		s := makeState(dupTargets, dupWorkspaces)
		_, err := ResolveTarget(s, "unknown/db")
		assert.Error(t, err, "expected unknown-workspace error")
	})
}

func TestProxyRejectsNilTarget(t *testing.T) {
	t.Parallel()
	err := Proxy(context.Background(), nil, "22", nil)
	assert.ErrorContains(t, err, "nil target")
}

func TestProxyRejectsNoEndpoints(t *testing.T) {
	t.Parallel()
	target := &state.Target{ID: "t-1", Name: "prod"}
	err := Proxy(context.Background(), target, "22", nil)
	assert.ErrorContains(t, err, "no endpoints configured")
}

func TestProxyReportsAllEndpointFailures(t *testing.T) {
	t.Parallel()
	target := &state.Target{
		ID:   "t-1",
		Name: "prod",
		// Unreachable addresses fail fast instead of hanging the test.
		Endpoints: []string{"127.0.0.1:1", "127.0.0.2:1"},
	}
	err := Proxy(context.Background(), target, "22", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all endpoints failed")
	assert.Contains(t, err.Error(), "127.0.0.1:1")
	assert.Contains(t, err.Error(), "127.0.0.2:1",
		"every endpoint failure must be reported")
}

// relayStubConn EOFs on read, so proxyIO completes without a real peer.
type relayStubConn struct {
	stub *relayStub
}

func (c *relayStubConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *relayStubConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *relayStubConn) CloseWrite() error {
	c.stub.halfClosed = true
	return nil
}

func (c *relayStubConn) Close() error { return nil }

type relayStub struct {
	calls      int
	halfClosed bool
	failOnCall bool
}

func (s *relayStub) dial(_ context.Context, _ *state.Target) (io.ReadWriteCloser, error) {
	// failOnCall lets the direct-success row fail loudly if relay ever dials.
	if s.failOnCall {
		return nil, fmt.Errorf("relay must not be dialed")
	}
	s.calls++
	return &relayStubConn{stub: s}, nil
}

// stdinEOF swaps [os.Stdin] for a closed pipe so proxyIO's stdin copy ends
// immediately instead of blocking on the test runner's stdin.
func stdinEOF(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, w.Close())
	old := os.Stdin
	os.Stdin = r //nolint:reassign // test isolation
	t.Cleanup(func() {
		os.Stdin = old //nolint:reassign // test isolation
		_ = r.Close()
	})
}

func TestProxyRelayFallback(t *testing.T) {
	stdinEOF(t)

	blackhole := "127.0.0.1:1"

	listener, lerr := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, lerr)
	defer func() { _ = listener.Close() }()
	liveEndpoint := listener.Addr().String()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	tests := []struct {
		name      string
		endpoints []string
		useRelay  bool
		forced    bool
		wantRelay bool
		wantErr   string
	}{
		{
			name:      "all endpoints failing falls back to relay",
			endpoints: []string{blackhole},
			useRelay:  true,
			wantRelay: true,
		},
		{
			name:      "no endpoints falls back to relay",
			useRelay:  true,
			wantRelay: true,
		},
		{
			name:      "forced relay skips direct dial",
			endpoints: []string{liveEndpoint},
			useRelay:  true,
			forced:    true,
			wantRelay: true,
		},
		{
			name:      "relay nil keeps endpoint dial errors",
			endpoints: []string{blackhole},
			wantErr:   "all endpoints failed",
		},
		{
			name:    "relay nil without endpoints reports config error",
			wantErr: "no endpoints configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &relayStub{}
			var relay RelayDialer
			if tt.useRelay {
				relay = stub.dial
			}
			target := &state.Target{ID: "t-1", Name: "prod", Endpoints: tt.endpoints}

			var err error
			if tt.forced {
				err = ProxyRelay(context.Background(), target, relay)
			} else {
				err = Proxy(context.Background(), target, "22", relay)
			}

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Zero(t, stub.calls)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, 1, stub.calls, "relay must be dialed exactly once")
			assert.True(t, stub.halfClosed, "stdin EOF must half-close the relay stream")
			if tt.forced {
				select {
				case <-accepted:
					t.Fatal("forced relay must not dial direct endpoints")
				default:
				}
			}
		})
	}

	t.Run("direct success does not use relay", func(t *testing.T) {
		stub := &relayStub{failOnCall: true}
		target := &state.Target{ID: "t-1", Name: "prod", Endpoints: []string{liveEndpoint}}

		err := Proxy(context.Background(), target, "22", stub.dial)
		require.NoError(t, err)

		select {
		case <-accepted:
		case <-time.After(time.Second):
			t.Fatal("direct connection was not established")
		}
	})
}

func TestNormalizeEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
		sshPort  string
		want     string
		wantErr  bool
	}{
		{"empty endpoint", "", "22", "", true},
		{"hostname without port", "example.com", "22", "example.com:22", false},
		{"hostname with port", "example.com:2222", "22", "example.com:2222", false},
		{"IPv4 without port", "192.168.1.1", "22", "192.168.1.1:22", false},
		{"IPv4 with port", "192.168.1.1:2222", "22", "192.168.1.1:2222", false},
		{"IPv6 without port", "2001:db8::1", "22", "[2001:db8::1]:22", false},
		{"IPv6 with port", "[2001:db8::1]:2222", "22", "[2001:db8::1]:2222", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeEndpoint(tt.endpoint, tt.sshPort)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
