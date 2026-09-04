package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsServiceAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"service account token", "nokku_sa_abc123", true},
		{"device session token", "sess-abc123", false},
		{"empty token", "", false},
		{"prefix only", "nokku_sa_", true},
		{"lookalike without prefix", "nokku_sa", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &State{Token: tt.token}
			assert.Equal(t, tt.want, s.IsServiceAccount())
		})
	}
}
