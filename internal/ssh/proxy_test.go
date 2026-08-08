package ssh

import (
	"testing"

	"github.com/nokku-sh/nk/internal/state"
)

func TestParseHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		host          string
		wantTarget    string
		wantWorkspace string
	}{
		{
			name:          "simple hostname",
			host:          "web-server",
			wantTarget:    "web-server",
			wantWorkspace: "",
		},
		{
			name:          "workspace/target format",
			host:          "production/web-server",
			wantTarget:    "web-server",
			wantWorkspace: "production",
		},
		{
			name:          "empty host",
			host:          "",
			wantTarget:    "",
			wantWorkspace: "",
		},
		{
			name:          "only workspace separator",
			host:          "/target",
			wantTarget:    "target",
			wantWorkspace: "",
		},
		{
			name:          "trailing separator",
			host:          "ws/",
			wantTarget:    "",
			wantWorkspace: "ws",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, workspace := parseHost(tt.host)
			if target != tt.wantTarget {
				t.Errorf("parseHost(%q) target = %q, want %q", tt.host, target, tt.wantTarget)
			}
			if workspace != tt.wantWorkspace {
				t.Errorf(
					"parseHost(%q) workspace = %q, want %q",
					tt.host,
					workspace,
					tt.wantWorkspace,
				)
			}
		})
	}
}

func TestResolveTargets(t *testing.T) {
	t.Parallel()

	makeState := func(targets []state.Target, workspaces []state.Workspace) *state.State {
		return &state.State{Cache: state.Cache{Targets: targets, Workspaces: workspaces}}
	}

	t.Run("finds target by name", func(t *testing.T) {
		s := makeState(
			[]state.Target{{ID: "1", Name: "prod"}, {ID: "2", Name: "staging"}},
			nil,
		)
		got := resolveTargets(s, "prod", "")
		if len(got) != 1 || got[0].ID != "1" {
			t.Errorf("resolveTargets = %+v", got)
		}
	})

	t.Run("returns empty when not found", func(t *testing.T) {
		s := makeState(
			[]state.Target{{ID: "1", Name: "prod"}},
			nil,
		)
		got := resolveTargets(s, "nonexistent", "")
		if len(got) != 0 {
			t.Errorf("expected empty, got %d", len(got))
		}
	})

	t.Run("filters by workspace name", func(t *testing.T) {
		s := makeState(
			[]state.Target{
				{ID: "1", Name: "db", WorkspaceID: "ws-1"},
				{ID: "2", Name: "db", WorkspaceID: "ws-2"},
			},
			[]state.Workspace{{ID: "ws-1", Name: "staging"}, {ID: "ws-2", Name: "production"}},
		)
		got := resolveTargets(s, "db", "staging")
		if len(got) != 1 || got[0].ID != "1" {
			t.Errorf("expected staging db, got %+v", got)
		}
	})

	t.Run("falls back to all targets when workspace filter has no match", func(t *testing.T) {
		s := makeState(
			[]state.Target{
				{ID: "1", Name: "db", WorkspaceID: "ws-1"},
			},
			[]state.Workspace{{ID: "ws-1", Name: "production"}},
		)
		got := resolveTargets(s, "db", "nonexistent-ws")
		if len(got) != 1 || got[0].ID != "1" {
			t.Errorf("expected fallback, got %+v", got)
		}
	})

	t.Run("empty targets returns empty", func(t *testing.T) {
		s := makeState(nil, nil)
		got := resolveTargets(s, "prod", "")
		if len(got) != 0 {
			t.Errorf("expected empty, got %d", len(got))
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
		{
			name:     "empty endpoint",
			endpoint: "",
			sshPort:  "22",
			want:     "",
			wantErr:  true,
		},
		{
			name:     "hostname without port",
			endpoint: "example.com",
			sshPort:  "22",
			want:     "example.com:22",
			wantErr:  false,
		},
		{
			name:     "hostname with port",
			endpoint: "example.com:2222",
			sshPort:  "22",
			want:     "example.com:2222",
			wantErr:  false,
		},
		{
			name:     "IPv4 without port",
			endpoint: "192.168.1.1",
			sshPort:  "22",
			want:     "192.168.1.1:22",
			wantErr:  false,
		},
		{
			name:     "IPv4 with port",
			endpoint: "192.168.1.1:2222",
			sshPort:  "22",
			want:     "192.168.1.1:2222",
			wantErr:  false,
		},
		{
			name:     "IPv6 without port",
			endpoint: "2001:db8::1",
			sshPort:  "22",
			want:     "[2001:db8::1]:22",
			wantErr:  false,
		},
		{
			name:     "IPv6 with port",
			endpoint: "[2001:db8::1]:2222",
			sshPort:  "22",
			want:     "[2001:db8::1]:2222",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeEndpoint(tt.endpoint, tt.sshPort)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("normalizeEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}
