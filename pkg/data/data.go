// Package data provides a way to store data in the request context.
package data

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/tomMoulard/fail2ban/pkg/logger"
)

type key string

const contextDataKey key = "data"

const headerSplitLimit = 2

type Data struct {
	RemoteIP string
}

// ServeHTTP sets data in the request context, to be extracted with GetData.
// If requestHeaderName is non-empty, the IP is read from that request header
// (e.g. "Cf-Connecting-Ip") instead of r.RemoteAddr.
// If the header is configured but missing, it falls back to r.RemoteAddr with a warning.
func ServeHTTP(w http.ResponseWriter, r *http.Request, requestHeaderName string) (*http.Request, error) {
	remoteIP, err := extractRemoteIP(r, requestHeaderName)
	if err != nil {
		return nil, err
	}

	d := &Data{RemoteIP: remoteIP}

	return r.WithContext(context.WithValue(r.Context(), contextDataKey, d)), nil
}

func extractRemoteIP(r *http.Request, requestHeaderName string) (string, error) {
	if requestHeaderName == "" {
		return remoteAddrIP(r)
	}

	headerValue := r.Header.Get(requestHeaderName)
	if headerValue == "" {
		return fallbackToRemoteAddr(r, requestHeaderName, "Plugin: FailToBan: header missing, falling back to RemoteAddr")
	}

	candidate := strings.TrimSpace(strings.SplitN(headerValue, ",", headerSplitLimit)[0])
	if net.ParseIP(candidate) != nil {
		return candidate, nil
	}

	return fallbackToRemoteAddr(r, requestHeaderName, "Plugin: FailToBan: invalid IP in header, falling back to RemoteAddr")
}

func fallbackToRemoteAddr(r *http.Request, headerName, warnMsg string) (string, error) {
	ip, err := remoteAddrIP(r)
	if err != nil {
		return "", err
	}

	logger.Warn(warnMsg,
		logger.WithHeader(headerName),
		logger.WithFallbackIP(ip),
	)

	return ip, nil
}

func remoteAddrIP(r *http.Request) (string, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("failed to split remote address %q: %w", r.RemoteAddr, err)
	}

	return ip, nil
}

// GetData returns the data stored in the request context.
func GetData(req *http.Request) *Data {
	if data, ok := req.Context().Value(contextDataKey).(*Data); ok {
		return data
	}

	return nil
}
