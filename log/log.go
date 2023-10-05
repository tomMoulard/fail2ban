//go:build !DEBUG

// Package log contains the logger mechanism for the plugin.
// Noop logger for non-debug builds.
package log

import (
	"io"
)

type Logger struct{}

func New(out io.Writer, prefix string, flag int) Logger {
	return Logger{}
}

func (l Logger) Println(v ...interface{}) {
}

func (l Logger) Printf(format string, v ...interface{}) {
}
