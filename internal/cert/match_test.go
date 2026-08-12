package cert

import (
	"strings"
	"testing"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
)

func testCA(id, name string) *nokkuv1.CertificateAuthority {
	idPtr, namePtr := id, name
	return &nokkuv1.CertificateAuthority{
		Id:   &idPtr,
		Name: &namePtr,
	}
}

func TestMatchX509CA(t *testing.T) {
	t.Parallel()
	cas := []*nokkuv1.CertificateAuthority{
		testCA("ca-1", "Production CA"),
		testCA("ca-2", "Staging CA"),
	}

	tests := []struct {
		name     string
		cas      []*nokkuv1.CertificateAuthority
		nameOrID string
		want     *nokkuv1.CertificateAuthority
		wantErr  string
	}{
		{
			name:    "no CAs available",
			cas:     nil,
			wantErr: "no X.509 certificate authorities",
		},
		{
			name:     "defaults to the only CA",
			cas:      cas[:1],
			nameOrID: "",
			want:     cas[0],
		},
		{
			name:     "ambiguous without a name",
			cas:      cas,
			nameOrID: "",
			wantErr:  "multiple X.509 CAs",
		},
		{
			name:     "match by ID",
			cas:      cas,
			nameOrID: "ca-2",
			want:     cas[1],
		},
		{
			name:     "match by name",
			cas:      cas,
			nameOrID: "Production CA",
			want:     cas[0],
		},
		{
			name:     "match by name is case-insensitive",
			cas:      cas,
			nameOrID: "production ca",
			want:     cas[0],
		},
		{
			name:     "unknown CA",
			cas:      cas,
			nameOrID: "ca-99",
			wantErr:  `"ca-99" not found`,
		},
		{
			name:     "ID wins over case-insensitive name match",
			cas:      cas,
			nameOrID: "ca-1",
			want:     cas[0],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := MatchX509CA(tt.cas, tt.nameOrID)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("MatchX509CA() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MatchX509CA() error = %v, want nil", err)
			}
			if got != tt.want {
				t.Fatalf("MatchX509CA() = %v, want %v", got.GetId(), tt.want.GetId())
			}
		})
	}
}
