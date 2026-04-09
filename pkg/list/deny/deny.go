// Package deny is a middleware that force denies requests from a list of IP addresses.
package deny

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/logger"
)

type deny struct {
	list            ipchecking.NetIPs
	enableBlockLogs bool
}

func New(ipList []string, enableBlockLogs bool) (*deny, error) {
	list, err := ipchecking.ParseNetIPs(ipList)
	if err != nil {
		return nil, fmt.Errorf("failed to create new net ips: %w", err)
	}

	return &deny{list: list, enableBlockLogs: enableBlockLogs}, nil
}

func (d *deny) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	reqData := data.GetData(r)
	if reqData == nil {
		return nil, errors.New("failed to get data from request context")
	}

	if d.list.Contains(reqData.RemoteIP) {
		if d.enableBlockLogs {
			logger.Info("Plugin: FailToBan: IP blocked",
				logger.WithIP(reqData.RemoteIP),
				logger.WithReason("static denylist"),
				logger.WithStatusCode(http.StatusTooManyRequests),
				logger.WithMethod(r.Method),
				logger.WithPath(r.URL.Path),
				logger.WithUA(r.UserAgent()),
			)
		}

		return &chain.Status{Return: true}, nil
	}

	return nil, nil
}
