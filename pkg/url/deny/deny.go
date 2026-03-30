// Package deny is a middleware that force denies requests from a list of IP addresses.
package deny

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/logger"
	"github.com/tomMoulard/fail2ban/pkg/utils/time"
)

type deny struct {
	regs            []*regexp.Regexp
	f2b             *fail2ban.Fail2Ban
	enableBlockLogs bool
}

func New(regs []*regexp.Regexp, f2b *fail2ban.Fail2Ban, enableBlockLogs bool) *deny {
	return &deny{
		regs:            regs,
		f2b:             f2b,
		enableBlockLogs: enableBlockLogs,
	}
}

func (d *deny) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	reqData := data.GetData(r)
	if reqData == nil {
		return nil, errors.New("failed to get data from request context")
	}

	d.f2b.MuIP.Lock()
	defer d.f2b.MuIP.Unlock()

	ip := d.f2b.IPs[reqData.RemoteIP]

	for _, reg := range d.regs {
		if reg.MatchString(r.URL.String()) {
			d.f2b.IPs[reqData.RemoteIP] = ipchecking.IPViewed{
				Viewed: time.Now(),
				Count:  ip.Count + 1,
				Denied: true,
			}

			if d.enableBlockLogs {
				logger.Info("Plugin: FailToBan: IP blocked",
					logger.WithIP(reqData.RemoteIP),
					logger.WithReason("url rule: "+reg.String()),
					logger.WithMethod(r.Method),
					logger.WithPath(r.URL.String()),
					logger.WithUA(r.UserAgent()),
				)
			}

			return &chain.Status{Return: true}, nil
		}
	}

	return nil, nil
}
