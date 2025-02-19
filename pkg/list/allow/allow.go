// Package allow is a middleware that force allows requests from a list of IP addresses.
package allow

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/jhalag/fail2ban/pkg/chain"
	"github.com/jhalag/fail2ban/pkg/data"
	"github.com/jhalag/fail2ban/pkg/ipchecking"
)

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

	fmt.Printf("data: %+v", data)

	if a.list.Contains(data.RemoteIP) {
		fmt.Printf("IP %s is allowed", data.RemoteIP)

		return &chain.Status{Break: true}, nil
	}

	fmt.Printf("IP %s not is allowed", data.RemoteIP)

	return nil, nil
}
