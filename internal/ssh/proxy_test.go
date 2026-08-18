package ssh

import (
	"testing"

	"github.com/nokku-sh/nk/internal/state"
)

func TestResolveTarget(t *testing.T) {
	t.Parallel()

	makeState := func(targets []state.Target, workspaces []state.Workspace) *state.State {
		return &state.State{Cache: state.Cache{Targets: targets, Workspaces: workspaces}}
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
		s := makeState(
			[]state.Target{{ID: "1", Name: "prod"}},
			nil,
		)
		got, err := ResolveTarget(s, "prod")
		if err != nil || got.ID != "1" {
			t.Errorf("ResolveTarget = %+v, %v", got, err)
		}
	})

	t.Run("disambiguates by workspace name", func(t *testing.T) {
		s := makeState(dupTargets, dupWorkspaces)
		got, err := ResolveTarget(s, "staging/db")
		if err != nil || got.ID != "1" {
			t.Errorf("ResolveTarget = %+v, %v", got, err)
		}
	})

	t.Run("disambiguates by workspace id", func(t *testing.T) {
		s := makeState(dupTargets, dupWorkspaces)
		got, err := ResolveTarget(s, "ws-2/db")
		if err != nil || got.ID != "2" {
			t.Errorf("ResolveTarget = %+v, %v", got, err)
		}
	})

	t.Run("rejects an ambiguous bare name", func(t *testing.T) {
		s := makeState(dupTargets, dupWorkspaces)
		if _, err := ResolveTarget(s, "db"); err == nil {
			t.Error("expected ambiguity error")
		}
	})

	t.Run("reports not found", func(t *testing.T) {
		s := makeState(nil, nil)
		if _, err := ResolveTarget(s, "missing"); err == nil {
			t.Error("expected not-found error")
		}
	})

	t.Run("reports unknown workspace", func(t *testing.T) {
		s := makeState(dupTargets, dupWorkspaces)
		if _, err := ResolveTarget(s, "unknown/db"); err == nil {
			t.Error("expected unknown-workspace error")
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
