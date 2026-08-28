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
			s:      &State{Targets: targets},
			target: "prod",
			want:   1,
			wantID: "1",
		},
		{
			name:   "target not found",
			s:      &State{Targets: targets},
			target: "nonexistent",
			want:   0,
		},
		{
			name:   "empty targets",
			s:      &State{Targets: []Target{}},
			target: "prod",
			want:   0,
		},
		{
			name:   "nil targets",
			s:      &State{Targets: nil},
			target: "prod",
			want:   0,
		},
		{
			name: "duplicate names across workspaces",
			s: &State{Targets: []Target{
				{ID: "1", Name: "prod"},
				{ID: "2", Name: "prod"},
			}},
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

func TestStateIsLoggedIn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		s    *State
		want bool
	}{
		{name: "service account token", s: &State{Token: "key.secret"}, want: true},
		{name: "session token", s: &State{SessionToken: "sess-1"}, want: true},
		{name: "nothing", s: &State{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.s.IsLoggedIn(); got != tt.want {
				t.Errorf("IsLoggedIn() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStateSubjectID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		s    *State
		want string
	}{
		{name: "service account takes precedence", s: &State{
			ServiceAccount: &ServiceAccount{ID: "sa-1"},
			User:           &User{ID: "user-1"},
		}, want: "sa-1"},
		{name: "user", s: &State{User: &User{ID: "user-1"}}, want: "user-1"},
		{name: "nobody", s: &State{}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.s.SubjectID(); got != tt.want {
				t.Errorf("SubjectID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStateHasCachedData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		s    *State
		want bool
	}{
		{name: "targets and identity", s: &State{
			Targets: []Target{{ID: "1", Name: "prod"}},
			User:    &User{ID: "user-1"},
		}, want: true},
		{name: "targets only", s: &State{
			Targets: []Target{{ID: "1", Name: "prod"}},
		}, want: false},
		{name: "identity only", s: &State{User: &User{ID: "user-1"}}, want: false},
		{name: "empty", s: &State{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.s.HasCachedData(); got != tt.want {
				t.Errorf("HasCachedData() = %v, want %v", got, tt.want)
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
			s:        &State{CAs: cas},
			caID:     "ca-1",
			expected: &CA{ID: "ca-1", Name: "Production CA", PublicKey: "key1"},
		},
		{
			name:     "ca not found",
			s:        &State{CAs: cas},
			caID:     "ca-999",
			expected: nil,
		},
		{
			name:     "empty cas",
			s:        &State{CAs: []CA{}},
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
