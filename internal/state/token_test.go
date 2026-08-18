package state

import "testing"

func TestIsServiceAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"service account API key", "key-123.secret-value", true},
		{"bare token without dot", "nks_abc", false},
		{"empty token", "", false},
		{"dot at start", ".secret", false},
		{"dot at end", "key.", false},
		{"no dot", "abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{Token: tt.token}
			if got := s.IsServiceAccount(); got != tt.want {
				t.Errorf("IsServiceAccount() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceAccountID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    *State
		want string
	}{
		{
			name: "service account set",
			s:    &State{Cache: Cache{ServiceAccount: &ServiceAccount{ID: "sa-1"}}},
			want: "sa-1",
		},
		{name: "no service account", s: &State{}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.ServiceAccountID(); got != tt.want {
				t.Errorf("ServiceAccountID() = %q, want %q", got, tt.want)
			}
		})
	}
}
