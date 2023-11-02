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

type Middleware struct {
	middleware *fail2ban.Fail2Ban
}

var mw = &Middleware{}

func init() {
	var cfg *fail2ban.Config
	if err := json.Unmarshal(handler.Host.GetConfig(), cfg); err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could not load config %v", err))
		os.Exit(1)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})

	hander, err := fail2ban.New(context.Background(), next, cfg, "fail2ban-WASM")
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could create middleware: %v", err))
		os.Exit(1)
	}

	var ok bool

	mw.middleware, ok = hander.(*fail2ban.Fail2Ban)
	if !ok {
		handler.Host.Log(api.LogLevelError, "Could create middleware")
		os.Exit(1)
	}
}

func main() {
	handler.HandleRequestFn = mw.handleRequest
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

// handleResponse implements a simple response middleware.
// NOOP for this particular plugin.
// func (mw *Middleware) handleResponse(_ uint32, _ api.Request, _ api.Response, _ bool) {
// }
