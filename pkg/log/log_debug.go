//go:build !DEBUG

// Package log contains the logger mechanism for the plugin.
// Debug logger for debug builds.
package log

import (
	"log"
	"os"
)

type Logger struct {
	*log.Logger
}

func New(prefix string) Logger {
	return Logger{log.New(os.Stdout, prefix+": ", log.Ldate|log.Ltime|log.Lshortfile)}
}
