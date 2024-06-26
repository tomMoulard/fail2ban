// Package allow is a middleware that force allows requests from a list of IP addresses.
package allow

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	logger "github.com/tomMoulard/fail2ban/pkg/log"
)

// l debug logger. noop by default.
var l = logger.New("list allow")

type allow struct {
	list ipchecking.NetIPs
}

func New(ipList []string) (*allow, error) {
	list, err := ipchecking.ParseNetIPs(ipList)
	if err != nil {
		return nil, fmt.Errorf("failed to create new net ips: %w", err)
	}

	return &allow{list: list}, nil
}

func (a *allow) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	data := data.GetData(r)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	l.Printf("data: %+v", data)

	if a.list.Contains(data.RemoteIP) {
		l.Printf("IP %s is allowed", data.RemoteIP)

		return &chain.Status{Break: true}, nil
	}

	l.Printf("IP %s not is allowed", data.RemoteIP)

	return nil, nil
}
