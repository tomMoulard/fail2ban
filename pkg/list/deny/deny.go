// Package deny is a middleware that force denies requests from a list of IP addresses.
package deny

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Workiz/traefik-fail2ban/pkg/chain"
	"github.com/Workiz/traefik-fail2ban/pkg/data"
	"github.com/Workiz/traefik-fail2ban/pkg/ipchecking"
	"github.com/Workiz/traefik-fail2ban/pkg/logger"
)

type deny struct {
	list ipchecking.NetIPs
}

func New(ipList []string) (*deny, error) {
	list, err := ipchecking.ParseNetIPs(ipList)
	if err != nil {
		return nil, fmt.Errorf("failed to create new net ips: %w", err)
	}

	return &deny{list: list}, nil
}

func (d *deny) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	data := data.GetData(r)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	if d.list.Contains(data.RemoteIP) {
		logger.Info("Plugin: FailToBan: IP blocked",
			logger.WithIP(data.RemoteIP),
			logger.WithReason("static denylist"),
			logger.WithMethod(r.Method),
			logger.WithPath(r.URL.Path),
			logger.WithUA(r.UserAgent()),
		)

		return &chain.Status{Return: true}, nil
	}

	return nil, nil
}
