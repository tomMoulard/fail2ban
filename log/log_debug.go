//go:build DEBUG

// Package log contains the logger mechanism for the plugin.
// Debug logger for debug builds.
package log

import (
	"io"
	"log"
)

type Logger struct {
	*log.Logger
}

func New(out io.Writer, prefix string, flag int) Logger {
	return Logger{log.New(out, prefix, flag)}
}
