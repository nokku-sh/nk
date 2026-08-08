package state

import (
	"testing"
)

func TestState_GetTargetsByName(t *testing.T) {
	t.Parallel()
	targets := []Target{
		{ID: "1", Name: "prod"},
		{ID: "2", Name: "staging"},
		{ID: "3", Name: "dev"},
	}

	tests := []struct {
		name   string
		s      *State
		target string
		want   int
		wantID string
	}{
		{
			name:   "find existing target",
			s:      &State{Cache: Cache{Targets: targets}},
			target: "prod",
			want:   1,
			wantID: "1",
		},
		{
			name:   "target not found",
			s:      &State{Cache: Cache{Targets: targets}},
			target: "nonexistent",
			want:   0,
		},
		{
			name:   "empty targets",
			s:      &State{Cache: Cache{Targets: []Target{}}},
			target: "prod",
			want:   0,
		},
		{
			name:   "nil targets",
			s:      &State{Cache: Cache{Targets: nil}},
			target: "prod",
			want:   0,
		},
		{
			name: "duplicate names across workspaces",
			s: &State{Cache: Cache{Targets: []Target{
				{ID: "1", Name: "prod"},
				{ID: "2", Name: "prod"},
			}}},
			target: "prod",
			want:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.s.GetTargetsByName(tt.target)
			if len(got) != tt.want {
				t.Errorf("GetTargetsByName(%q) = %d results, want %d", tt.target, len(got), tt.want)
			}
			if tt.want == 1 && len(got) == 1 && got[0].ID != tt.wantID {
				t.Errorf(
					"GetTargetsByName(%q)[0].ID = %q, want %q",
					tt.target,
					got[0].ID,
					tt.wantID,
				)
			}
		})
	}
}

func TestState_GetCAByID(t *testing.T) {
	t.Parallel()
	cas := []CA{
		{ID: "ca-1", Name: "Production CA", PublicKey: "key1"},
		{ID: "ca-2", Name: "Staging CA", PublicKey: "key2"},
	}

	tests := []struct {
		name     string
		s        *State
		caID     string
		expected *CA
	}{
		{
			name:     "find existing ca",
			s:        &State{Cache: Cache{CAs: cas}},
			caID:     "ca-1",
			expected: &CA{ID: "ca-1", Name: "Production CA", PublicKey: "key1"},
		},
		{
			name:     "ca not found",
			s:        &State{Cache: Cache{CAs: cas}},
			caID:     "ca-999",
			expected: nil,
		},
		{
			name:     "empty cas",
			s:        &State{Cache: Cache{CAs: []CA{}}},
			caID:     "ca-1",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.s.GetCAByID(tt.caID)
			switch {
			case got == nil && tt.expected != nil:
				t.Errorf("State.GetCAByID(%q) = nil, want non-nil", tt.caID)
			case got != nil && tt.expected == nil:
				t.Errorf("State.GetCAByID(%q) = non-nil, want nil", tt.caID)
			case got != nil && tt.expected != nil && (got.ID != tt.expected.ID || got.Name != tt.expected.Name):
				t.Errorf("State.GetCAByID(%q) = %+v, want %+v", tt.caID, got, tt.expected)
			}
		})
	}
}
