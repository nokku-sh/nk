package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
			assert.Len(t, got, tt.want)
			if tt.want == 1 {
				assert.Equal(t, tt.wantID, got[0].ID)
			}
		})
	}
}

func TestState_SessionValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		s    *State
		want bool
	}{
		{
			name: "no credentials",
			s:    &State{},
			want: false,
		},
		{
			name: "service account token",
			s:    &State{Token: "nokku_sa_k.s"},
			want: true,
		},
		{
			name: "session token without known expiry",
			s:    &State{SessionToken: "tok"},
			want: true,
		},
		{
			name: "session token not expired",
			s: &State{
				SessionToken:     "tok",
				SessionExpiresAt: time.Now().Add(time.Hour),
			},
			want: true,
		},
		{
			name: "session token expired",
			s: &State{
				SessionToken:     "tok",
				SessionExpiresAt: time.Now().Add(-time.Minute),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.s.SessionValid())
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
			assert.Equal(t, tt.want, tt.s.HasCachedData())
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
			assert.Equal(t, tt.expected, tt.s.GetCAByID(tt.caID))
		})
	}
}
