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
