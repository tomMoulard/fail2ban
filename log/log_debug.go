//go:build DEBUG

// Package log contains the logger mechanism for the plugin.
// Debug logger for debug builds.
package log

import (
	"io"
	"log"
)

type Logger struct {
	logger *log.Logger
}

func New(out io.Writer, prefix string, flag int) Logger {
	return Logger{logger: log.New(out, prefix, flag)}
}

func (l Logger) Println(v ...interface{}) {
	l.logger.Println(v...)
}

func (l Logger) Printf(format string, v ...interface{}) {
	l.logger.Printf(format, v...)
}
