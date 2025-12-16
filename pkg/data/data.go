// Package data provides a way to store data in the request context.
package data

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/tomMoulard/fail2ban/pkg/rules"
)

// Data holds request context data.
type Data struct {
	RemoteIP string
}

type key int

const contextDataKey key = iota

// GetRemoteIP extracts the remote IP from the request using the specified source criterion.
func GetRemoteIP(r *http.Request, sourceCriterion rules.SourceCriterion) (string, error) {
	// If a specific header is configured, use it as the source
	if sourceCriterion.RequestHeaderName != nil && *sourceCriterion.RequestHeaderName != "" {
		if headerIP := r.Header.Get(*sourceCriterion.RequestHeaderName); headerIP != "" {
			var depth int

			if sourceCriterion.IPStrategy != nil && sourceCriterion.IPStrategy.Depth != nil {
				depth = *sourceCriterion.IPStrategy.Depth
			}

			return extractIPFromHeader(headerIP, depth)
		}
	}

	// Fall back to RemoteAddr if no header is specified or no valid IP found
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("failed to parse remote address: %w", err)
	}

	return ip, nil
}

// extractIPFromHeader extracts an IP address from a header value using the specified depth.
// If depth <= 0, returns the first IP in the list.
func extractIPFromHeader(headerValue string, depth int) (string, error) {
	// Split and clean the IPs
	ips := strings.Split(headerValue, ",")

	if len(ips) == 0 {
		return "", errors.New("no IP addresses found in header value")
	}

	for i, ip := range ips {
		ips[i] = strings.TrimSpace(ip)
	}

	// Select the appropriate IP based on depth
	var ip string
	if depth <= 0 || depth > len(ips) {
		// Use first IP if depth is invalid or too large
		ip = ips[0]
	} else {
		// Get the IP at the specified depth (counting from right)
		ip = ips[len(ips)-depth]
	}

	// Validate the IP
	if parsedIP := net.ParseIP(ip); parsedIP == nil {
		return "", fmt.Errorf("invalid IP address in header: %q", ip)
	}

	return ip, nil
}

// ServeHTTP adds request data to the context.
func ServeHTTP(w http.ResponseWriter, r *http.Request, sourceCriterion rules.SourceCriterion) (*http.Request, error) {
	remoteIP, err := GetRemoteIP(r, sourceCriterion)
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
