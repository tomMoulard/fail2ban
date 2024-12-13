// Package data provides a way to store data in the request context.
package data

import (
	"context"
	"net/http"
	"strings"
)

type key string

const (
	contextDataKey key = "data"
	remoteIPKey    key = "remoteIP"
)

type Data struct {
	RemoteIP string
}

// Config holds the configuration for the data package.
type Config struct {
	IPHeader string
}

var globalConfig Config

// SetConfig sets the global configuration.
func SetConfig(cfg Config) {
	globalConfig = cfg
}

func getIPFromHeader(header, value string) string {
	if header == "X-Forwarded-For" {
		if i := strings.IndexByte(value, ','); i != -1 {
			return value[:i]
		}
	}

	return value
}

// ServeHTTP sets data in the request context, to be extracted with GetData.
func ServeHTTP(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	remoteIP := r.RemoteAddr
	if i := strings.IndexByte(remoteIP, ':'); i != -1 {
		remoteIP = remoteIP[:i]
	}

	// Get real IP from configured header
	if ipHeader := globalConfig.IPHeader; ipHeader != "" {
		if realIP := r.Header.Get(ipHeader); realIP != "" {
			remoteIP = getIPFromHeader(ipHeader, realIP)
		}
	}

	data := &Data{
		RemoteIP: remoteIP,
	}

	// Store data in both keys for backward compatibility
	ctx := context.WithValue(r.Context(), contextDataKey, data)
	ctx = context.WithValue(ctx, remoteIPKey, data)

	return r.WithContext(ctx), nil
}

// GetData returns the data stored in the request context.
func GetData(req *http.Request) *Data {
	if data, ok := req.Context().Value(contextDataKey).(*Data); ok {
		return data
	}

	// Try the remoteIPKey as fallback
	if data, ok := req.Context().Value(remoteIPKey).(*Data); ok {
		return data
	}

	return nil
}
