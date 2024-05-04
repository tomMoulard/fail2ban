//go:build TEST

// Package time is a wrapper over the stdlib time package.
package time

import "time"

func Now() time.Time {
	return time.Date(2021, 10, 21, 14, 44, 38, 0, time.UTC) // The first commit here !
}
