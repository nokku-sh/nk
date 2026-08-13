package doctor

import "testing"

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
			if got := r.ExitCode(); got != tt.want {
				t.Fatalf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCertID(t *testing.T) {
	if got := certID("/tmp/nk/certs/abc123-cert.pub"); got != "abc123" {
		t.Fatalf("certID() = %q, want %q", got, "abc123")
	}
}
