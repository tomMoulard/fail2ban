//go:build !TEST

// Package time is a wrapper over the stdlib time package.
package time

import "time"

func Now() time.Time {
	return time.Now()
}
