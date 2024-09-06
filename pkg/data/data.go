// Package data provides a way to store data in the request context.
package data

import (
	"context"
	"fmt"
	"net"
	"net/http"
)

type key string

const contextDataKey key = "data"

type Data struct {
	RemoteIP string
}

// ServeHTTP sets data in the request context, to be extracted with GetData.
func ServeHTTP(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to split remote address %q: %w", r.RemoteAddr, err)
	}

	data := &Data{
		RemoteIP: remoteIP,
	}

	fmt.Printf("data: %+v", data)

	return r.WithContext(context.WithValue(r.Context(), contextDataKey, data)), nil
}

// GetData returns the data stored in the request context.
func GetData(req *http.Request) *Data {
	if data, ok := req.Context().Value(contextDataKey).(*Data); ok {
		return data
	}

	return nil
}
