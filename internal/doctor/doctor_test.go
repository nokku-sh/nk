package doctor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		name   string
		checks []Check
		want   int
	}{
		{"all ok", []Check{{Status: StatusOK}, {Status: StatusInfo}}, 0},
		{"warning", []Check{{Status: StatusOK}, {Status: StatusWarn}}, 1},
		{"failure dominates warning", []Check{{Status: StatusWarn}, {Status: StatusFail}}, 2},
		{"empty", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Report{Checks: tt.checks}
			assert.Equal(t, tt.want, r.ExitCode())
		})
	}
}

func TestCertID(t *testing.T) {
	assert.Equal(t, "abc123", certID("/tmp/nk/certs/abc123-cert.pub"))
}
