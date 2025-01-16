// Package data provides a way to store data in the request context.
package data

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Data holds request context data.
type Data struct {
	RemoteIP string
}

type key int

const contextDataKey key = iota

// GetRemoteIP extracts the remote IP from the request, optionally using a custom header.
func GetRemoteIP(r *http.Request, sourceIPHeader string) (string, error) {
	// First check the custom header if specified
	if sourceIPHeader != "" {
		if headerIP := r.Header.Get(sourceIPHeader); headerIP != "" {
			// Handle potential comma-separated list (e.g. X-Forwarded-For)
			ips := strings.Split(headerIP, ",")
			// Use the first (leftmost) IP in the list
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip, nil
			}

			return "", fmt.Errorf("invalid IP address in header %s: %s", sourceIPHeader, headerIP)
		}
	}

	// Fall back to RemoteAddr if no header specified or no valid IP found in header.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("failed to parse remote address: %w", err)
	}

	return ip, nil
}

// ServeHTTP adds request data to the context.
func ServeHTTP(w http.ResponseWriter, r *http.Request, sourceIPHeader string) (*http.Request, error) {
	remoteIP, err := GetRemoteIP(r, sourceIPHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote IP: %w", err)
	}

	data := &Data{
		RemoteIP: remoteIP,
	}

	return r.WithContext(context.WithValue(r.Context(), contextDataKey, data)), nil
}

// GetData retrieves request data from the context.
func GetData(r *http.Request) *Data {
	if r == nil {
		return nil
	}

	data, ok := r.Context().Value(contextDataKey).(*Data)
	if !ok {
		return nil
	}

	return data
}
