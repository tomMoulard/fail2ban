// Package deny is a middleware that force denies requests from a list of IP addresses.
package deny

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/jhalag/fail2ban/pkg/chain"
	"github.com/jhalag/fail2ban/pkg/data"
	"github.com/jhalag/fail2ban/pkg/ipchecking"
)

type deny struct {
	list ipchecking.NetIPs
}

func New(ipList []string) (*deny, error) {
	list, err := ipchecking.ParseNetIPs(ipList)
	if err != nil {
		return nil, fmt.Errorf("failed to create new net ips: %w", err)
	}

	return &deny{list: list}, nil
}

func (d *deny) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	data := data.GetData(r)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	fmt.Printf("data: %+v", data)

	if d.list.Contains(data.RemoteIP) {
		fmt.Printf("IP %s is denied", data.RemoteIP)

		return &chain.Status{Return: true}, nil
	}

	fmt.Printf("IP %s not is denied", data.RemoteIP)

	return nil, nil
}
