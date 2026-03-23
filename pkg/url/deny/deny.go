// Package deny is a middleware that force denies requests from a list of IP addresses.
package deny

import (
	"errors"
	"log"
	"net/http"
	"regexp"

	"github.com/Workiz/traefik-fail2ban/pkg/chain"
	"github.com/Workiz/traefik-fail2ban/pkg/data"
	"github.com/Workiz/traefik-fail2ban/pkg/fail2ban"
	"github.com/Workiz/traefik-fail2ban/pkg/ipchecking"
	"github.com/Workiz/traefik-fail2ban/pkg/utils/time"
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

			log.Printf("Plugin: FailToBan: IP %s blocked (URL rule %q matched %q) method=%s ua=%q",
				data.RemoteIP, reg.String(), r.URL.String(), r.Method, r.UserAgent())

			return &chain.Status{Return: true}, nil
		}
	}

	return nil, nil
}
