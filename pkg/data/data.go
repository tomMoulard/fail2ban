// Package data provides a way to store data in the request context.
package data

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type key string

const contextDataKey key = "data"

type Data struct {
	RemoteIP string
}

// ServeHTTP sets data in the request context, to be extracted with GetData.
// If requestHeaderName is non-empty, the IP is read from that request header
// (e.g. "Cf-Connecting-Ip") instead of r.RemoteAddr.
func ServeHTTP(w http.ResponseWriter, r *http.Request, requestHeaderName string) (*http.Request, error) {
	var remoteIP string

	if requestHeaderName != "" {
		headerValue := r.Header.Get(requestHeaderName)
		if headerValue == "" {
			return nil, fmt.Errorf("header %q is missing from request", requestHeaderName)
		}

		remoteIP = strings.TrimSpace(strings.SplitN(headerValue, ",", 2)[0])
	} else {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to split remote address %q: %w", r.RemoteAddr, err)
		}

		remoteIP = ip
	}

	d := &Data{
		RemoteIP: remoteIP,
	}

	return r.WithContext(context.WithValue(r.Context(), contextDataKey, d)), nil
}

// GetData returns the data stored in the request context.
func GetData(req *http.Request) *Data {
	if data, ok := req.Context().Value(contextDataKey).(*Data); ok {
		return data
	}

	return nil
}
