//go:build WASM

// Package main contains the WASM mechanism for the plugin.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"

	"github.com/tomMoulard/fail2ban"
)

func main() {
	var cfg fail2ban.Config
	if err := json.Unmarshal(handler.Host.GetConfig(), &cfg); err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could not load config %v", err))
		os.Exit(1)
	}

	mw, err := New(cfg)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could not create middleware: %v", err))
		os.Exit(1)
	}

	handler.HandleRequestFn = mw.handleRequest
}

type Middleware struct {
	middleware *fail2ban.Fail2Ban
}

// New creates a new middleware.
func New(cfg fail2ban.Config) (*Middleware, error) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})

	hander, err := fail2ban.New(context.Background(), next, &cfg, "fail2ban-WASM")
	if err != nil {
		return nil, fmt.Errorf("Could not create fail2ban middleware: %w", err)
	}

	var mw = &Middleware{}
	var ok bool
	mw.middleware, ok = hander.(*fail2ban.Fail2Ban)
	if !ok {
		handler.Host.Log(api.LogLevelError, "Could not create middleware")
		os.Exit(1)
	}

	return mw, nil
}

// handleRequest implements a simple request middleware.
// Wraps the Fail2ban plugin.
func (mw *Middleware) handleRequest(req api.Request, resp api.Response) (next bool, reqCtx uint32) {
	remoteIP, found := req.Headers().Get("Host")
	if !found {
		handler.Host.Log(api.LogLevelError, "Could not get Host header")

		return
	}

	next = mw.middleware.ShouldAllow(remoteIP, req.GetURI())

	return
}
