// Package allow is a middleware that force allows requests from a list of regexps.
package allow

import (
	"net/http"
	"regexp"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	logger "github.com/tomMoulard/fail2ban/pkg/log"
)

// l debug logger. noop by default.
var l = logger.New("url allow")

type allow struct {
	regs []*regexp.Regexp
}

func New(regs []*regexp.Regexp) *allow {
	return &allow{regs: regs}
}

func (a *allow) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	for _, reg := range a.regs {
		if reg.MatchString(r.URL.String()) {
			l.Printf("url %s not allowed", r.URL.String())

			return &chain.Status{Break: true}, nil
		}
	}

	l.Printf("url %s not is allowed", r.URL.String())

	return nil, nil
}
