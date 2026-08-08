package util

import (
	"math"
	"time"
)

func Uint64ToUnixTime(t uint64) time.Time {
	if t > math.MaxInt64 {
		return time.Unix(math.MaxInt64, 0)
	}
	return time.Unix(int64(t), 0)
}
