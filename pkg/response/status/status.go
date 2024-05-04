// Package status is a middleware that denies requests from the status of the answer
package status

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
	logger "github.com/tomMoulard/fail2ban/pkg/log"
)

// l debug logger. noop by default.
var l = logger.New(os.Stdout, "DEBUG: status: ", log.Ldate|log.Ltime|log.Lshortfile)

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
		l.Println("data is nil")

		return
	}

	l.Printf("data: %+v", data)

	catcher := newCodeCatcher(w, s.codeRanges)
	s.next.ServeHTTP(catcher, r)
	w.WriteHeader(catcher.getCode())

	l.Printf("catcher: %+v", *catcher)

	if !catcher.isFilteredCode() {
		return
	}

	s.f2b.ShouldAllow(data.RemoteIP)
}
