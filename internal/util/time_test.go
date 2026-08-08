package util

import (
	"math"
	"testing"
	"time"
)

func TestUint64ToUnixTime(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tests := []struct {
		name string
		t    uint64
		want time.Time
	}{
		{
			name: "zero",
			t:    0,
			want: time.Unix(0, 0),
		},
		{
			name: "unix epoch",
			t:    1700000000,
			want: time.Unix(1700000000, 0),
		},
		{
			name: "max int64 overflow",
			t:    math.MaxUint64,
			want: time.Unix(math.MaxInt64, 0),
		},
		{
			name: "near max int64",
			t:    math.MaxInt64 - 1,
			want: time.Unix(math.MaxInt64-1, 0),
		},
		{
			name: "recent time",

			t:    uint64(now.Unix()),
			want: time.Unix(now.Unix(), 0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Uint64ToUnixTime(tt.t)
			if !got.Equal(tt.want) {
				t.Errorf("Uint64ToUnixTime(%d) = %v, want %v", tt.t, got, tt.want)
			}
		})
	}
}
