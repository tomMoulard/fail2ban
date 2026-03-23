// Package logger provides structured JSON logging for the fail2ban plugin.
package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Event represents a structured log entry.
type Event struct {
	Time       string `json:"time"`
	Level      string `json:"level"`
	Msg        string `json:"msg"`
	IP         string `json:"ip,omitempty"`
	Reason     string `json:"reason,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	UA         string `json:"ua,omitempty"`
	Header     string `json:"header,omitempty"`
	FallbackIP string `json:"fallback_ip,omitempty"`
	Err        string `json:"error,omitempty"`
}

// Info writes an info-level JSON log entry to stdout.
func Info(msg string, fields ...func(*Event)) {
	write("info", msg, fields...)
}

// Warn writes a warn-level JSON log entry to stdout.
func Warn(msg string, fields ...func(*Event)) {
	write("warn", msg, fields...)
}

// Error writes an error-level JSON log entry to stdout.
func Error(msg string, fields ...func(*Event)) {
	write("error", msg, fields...)
}

func write(level, msg string, fields ...func(*Event)) {
	e := &Event{
		Time:  time.Now().UTC().Format(time.RFC3339),
		Level: level,
		Msg:   msg,
	}

	for _, f := range fields {
		f(e)
	}

	b, _ := json.Marshal(e)
	fmt.Fprintln(os.Stdout, string(b))
}

// WithIP sets the IP field.
func WithIP(ip string) func(*Event) {
	return func(e *Event) { e.IP = ip }
}

// WithReason sets the Reason field.
func WithReason(reason string) func(*Event) {
	return func(e *Event) { e.Reason = reason }
}

// WithStatusCode sets the StatusCode field.
func WithStatusCode(code int) func(*Event) {
	return func(e *Event) { e.StatusCode = code }
}

// WithMethod sets the Method field.
func WithMethod(method string) func(*Event) {
	return func(e *Event) { e.Method = method }
}

// WithPath sets the Path field.
func WithPath(path string) func(*Event) {
	return func(e *Event) { e.Path = path }
}

// WithUA sets the UA (user-agent) field.
func WithUA(ua string) func(*Event) {
	return func(e *Event) { e.UA = ua }
}

// WithHeader sets the Header field.
func WithHeader(header string) func(*Event) {
	return func(e *Event) { e.Header = header }
}

// WithFallbackIP sets the FallbackIP field.
func WithFallbackIP(ip string) func(*Event) {
	return func(e *Event) { e.FallbackIP = ip }
}

// WithErr sets the Err field.
func WithErr(err string) func(*Event) {
	return func(e *Event) { e.Err = err }
}
