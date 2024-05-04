// Package deny is a middleware that force denies requests from a list of IP addresses.
package deny

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	logger "github.com/tomMoulard/fail2ban/pkg/log"
)

// l debug logger. noop by default.
var l = logger.New(os.Stdout, "DEBUG: list deny: ", log.Ldate|log.Ltime|log.Lshortfile)

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

func (a *deny) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	data := data.GetData(r)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	l.Printf("data: %+v", data)

	if a.list.Contains(data.RemoteIP) {
		l.Printf("IP %s is denied", data.RemoteIP)

		return &chain.Status{Return: true}, nil
	}

	l.Printf("IP %s not is denied", data.RemoteIP)

	return nil, nil
}
