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
	regs []*regexp.Regexp

	f2b *fail2ban.Fail2Ban
}

func New(regs []*regexp.Regexp, f2b *fail2ban.Fail2Ban) *deny {
	return &deny{
		regs: regs,
		f2b:  f2b,
	}
}

func (d *deny) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	data := data.GetData(r)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	d.f2b.MuIP.Lock()
	defer d.f2b.MuIP.Unlock()

	ip := d.f2b.IPs[data.RemoteIP]

	for _, reg := range d.regs {
		if reg.MatchString(r.URL.String()) {
			d.f2b.IPs[data.RemoteIP] = ipchecking.IPViewed{
				Viewed: time.Now(),
				Count:  ip.Count + 1,
				Denied: true,
			}

			logger.Info("Plugin: FailToBan: IP blocked",
				logger.WithIP(data.RemoteIP),
				logger.WithReason("url rule: "+reg.String()),
				logger.WithMethod(r.Method),
				logger.WithPath(r.URL.String()),
				logger.WithUA(r.UserAgent()),
			)

			return &chain.Status{Return: true}, nil
		}
	}

	return nil, nil
}
