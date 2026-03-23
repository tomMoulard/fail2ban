// Package status is a middleware that denies requests from the status of the answer
package status

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Workiz/traefik-fail2ban/pkg/data"
	"github.com/Workiz/traefik-fail2ban/pkg/fail2ban"
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
	data := data.GetData(r)
	if data == nil {
		return
	}

	catcher := newCodeCatcher(w, s.codeRanges)
	s.next.ServeHTTP(catcher, r)

	if !catcher.isFilteredCode() {
		for k, vv := range catcher.Header() {
			w.Header().Set(k, strings.Join(vv, ", "))
		}

		w.WriteHeader(catcher.getCode())

		return
	}

	catcher.allowedRequest = s.f2b.ShouldAllow(data.RemoteIP)
	if !catcher.allowedRequest {
		log.Printf("Plugin: FailToBan: IP %s blocked (status code ban: %d) method=%s path=%s ua=%q",
			data.RemoteIP, catcher.getCode(), r.Method, r.URL.Path, r.UserAgent())
		w.WriteHeader(http.StatusTooManyRequests)

		return
	}

	for k, vv := range catcher.Header() {
		w.Header().Set(k, strings.Join(vv, ", "))
	}

	w.WriteHeader(catcher.getCode())

	if _, err := w.Write(catcher.bytes); err != nil {
		log.Printf("Plugin: FailToBan: failed to write response: %v", err)
	}
}
