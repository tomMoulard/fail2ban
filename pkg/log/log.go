//go:build DEBUG

// Package log contains the logger mechanism for the plugin.
// Noop logger for non-debug builds.
package log

import (
	"log"
)

type Logger struct {
	*log.Logger
}

func New(string) Logger {
	return Logger{}
}

func (l Logger) Printf(format string, v ...interface{}) {}

func (l Logger) Println(v ...interface{}) {}
