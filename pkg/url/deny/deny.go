// Package deny is a middleware that force denies requests from a list of IP addresses.
package deny

import (
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	logger "github.com/tomMoulard/fail2ban/pkg/log"
	"github.com/tomMoulard/fail2ban/pkg/utils/time"
)

// l debug logger. noop by default.
var l = logger.New(os.Stdout, "DEBUG: url deny: ", log.Ldate|log.Ltime|log.Lshortfile)

type deny struct {
	regs []*regexp.Regexp

	muIP     *sync.Mutex
	ipViewed *map[string]ipchecking.IPViewed
}

func New(regs []*regexp.Regexp, muIP *sync.Mutex, ipViewed *map[string]ipchecking.IPViewed) *deny {
	return &deny{
		regs:     regs,
		muIP:     muIP,
		ipViewed: ipViewed,
	}
}

func (d *deny) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	data := data.GetData(r)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	l.Printf("data: %+v", data)

	d.muIP.Lock()
	defer d.muIP.Unlock()

	ip := (*d.ipViewed)[data.RemoteIP]

	for _, reg := range d.regs {
		if reg.MatchString(r.URL.String()) {
			(*d.ipViewed)[data.RemoteIP] = ipchecking.IPViewed{
				Viewed: time.Now(),
				Count:  ip.Count + 1,
				Denied: true,
			}

			l.Printf("Url (%q) was matched by regexpBan: %q", r.URL.String(), reg.String())

			return &chain.Status{Return: true}, nil
		}
	}

	return nil, nil
}
