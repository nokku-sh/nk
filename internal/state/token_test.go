package state

import "testing"

func TestIsServiceAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"service account token", "nks_abc", true},
		{"user token", "nkc_abc", false},
		{"empty token", "", false},
		{"unknown token", "abc", false},
		{"prefix only no underscore", "nks", false},
		{"mixed case not matched", "NKS_abc", false},
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
