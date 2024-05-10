// Package data provides a way to store data in the request context.
package data

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	logger "github.com/tomMoulard/fail2ban/pkg/log"
)

// l debug logger. noop by default.
var l = logger.New(os.Stdout, "DEBUG: data: ", log.Ldate|log.Ltime|log.Lshortfile)

type key string

const contextDataKey key = "data"

type Data struct {
	RemoteIP string
}

// extractClientIP attempts to extract the client IP address from the request headers, prioritizing the X-Forwarded-For header.
func extractClientIP(r *http.Request) string {
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// If X-Forwarded-For header is present, take the first IP from the list
		parts := strings.Split(xForwardedFor, ",")
		return strings.TrimSpace(parts[0])
	}

	// Fallback to remote address from the connection
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		l.Printf("failed to split remote address %q: %s", r.RemoteAddr, err)
		return ""
	}

	return remoteIP
}

// ServeHTTP sets data in the request context, to be extracted with GetData.
func ServeHTTP(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	clientIP := extractClientIP(r)

	data := &Data{
		RemoteIP: clientIP,
	}

	l.Printf("data: %+v", data)

	return r.WithContext(context.WithValue(r.Context(), contextDataKey, data)), nil
}

// GetData returns the data stored in the request context.
func GetData(req *http.Request) *Data {
	if data, ok := req.Context().Value(contextDataKey).(*Data); ok {
		return data
	}

	return nil
}
