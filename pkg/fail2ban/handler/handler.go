// Package handler provides a fail2ban middleware.
package handler

import (
	"errors"
	"net/http"

	"github.com/Workiz/traefik-fail2ban/pkg/chain"
	"github.com/Workiz/traefik-fail2ban/pkg/data"
	"github.com/Workiz/traefik-fail2ban/pkg/fail2ban"
	"github.com/Workiz/traefik-fail2ban/pkg/logger"
)

type handler struct {
	f2b *fail2ban.Fail2Ban
}

func New(f2b *fail2ban.Fail2Ban) *handler {
	return &handler{f2b: f2b}
}

// ServeHTTP iterates over every headers to match the ones specified in the
// configuration and return nothing if regexp failed.
func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) (*chain.Status, error) {
	data := data.GetData(req)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	if !h.f2b.IsNotBanned(data.RemoteIP) {
		logger.Info("Plugin: FailToBan: IP blocked",
			logger.WithIP(data.RemoteIP),
			logger.WithReason("banned"),
			logger.WithMethod(req.Method),
			logger.WithPath(req.URL.Path),
			logger.WithUA(req.UserAgent()),
		)

		return &chain.Status{Return: true}, nil
	}

	return nil, nil
}
