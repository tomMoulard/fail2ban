// Package allow is a middleware that force allows requests from a list of regexps.
package allow

import (
	"net/http"
	"regexp"

	"github.com/Workiz/traefik-fail2ban/pkg/chain"
)

type allow struct {
	regs []*regexp.Regexp
}

func New(regs []*regexp.Regexp) *allow {
	return &allow{regs: regs}
}

func (a *allow) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	for _, reg := range a.regs {
		if reg.MatchString(r.URL.String()) {
			return &chain.Status{Break: true}, nil
		}
	}

	return nil, nil
}
