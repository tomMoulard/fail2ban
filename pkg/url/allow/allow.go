// Package allow is a middleware that force allows requests from a list of regexps.
package allow

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/tomMoulard/fail2ban/pkg/chain"
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
			fmt.Printf("url %s not allowed", r.URL.String())

			return &chain.Status{Break: true}, nil
		}
	}

	fmt.Printf("url %s not is allowed", r.URL.String())

	return nil, nil
}
