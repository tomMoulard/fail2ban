// Package status is a middleware that denies requests from the status of the answer
package status

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
)

type status struct {
	next       http.Handler
	codeRanges HTTPCodeRanges
	f2b        *fail2ban.Fail2Ban
}

func New(next http.Handler, statusCode string, f2b *fail2ban.Fail2Ban) (*status, error) {
	codeRanges, err := NewHTTPCodeRanges(strings.Split(statusCode, ","))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP code ranges: %w", err)
	}

	return &status{
		next:       next,
		codeRanges: codeRanges,
		f2b:        f2b,
	}, nil
}

func (s *status) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("status handler")

	data := data.GetData(r)
	if data == nil {
		fmt.Print("data is nil")

		return
	}

	fmt.Printf("data: %+v", data)

	catcher := newCodeCatcher(w, s.codeRanges)
	s.next.ServeHTTP(catcher, r)

	fmt.Printf("catcher: %+v", *catcher)

	if !catcher.isFilteredCode() {
		w.WriteHeader(catcher.getCode())

		return
	}

	catcher.allowedRequest = s.f2b.ShouldAllow(data.RemoteIP)
	if !catcher.allowedRequest {
		fmt.Printf("IP %s is banned", data.RemoteIP)
		w.WriteHeader(http.StatusForbidden)

		return
	}

	fmt.Printf("IP %s is allowed", data.RemoteIP)
	w.WriteHeader(catcher.getCode())

	if _, err := w.Write(catcher.bytes); err != nil {
		fmt.Printf("failed to write to response: %v\n", err)
	}
}
