//go:build DEBUG

// Package log contains the logger mechanism for the plugin.
// Debug logger for debug builds.
package log

import (
	"io"
	"log"
)

func New(out io.Writer, prefix string, flag int) *log.Logger {
	return log.New(out, prefix, flag)
}
