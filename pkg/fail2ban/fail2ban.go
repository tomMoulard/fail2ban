// Package fail2ban provides a fail2ban implementation.
package fail2ban

import (
	"fmt"
	"sync"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	utime "github.com/tomMoulard/fail2ban/pkg/utils/time"
)

// Fail2Ban is a fail2ban implementation.
type Fail2Ban struct {
	rules rules.RulesTransformed

	MuIP      sync.Mutex
	IPs       map[string]ipchecking.IPViewed
	allowList ipchecking.NetIPs
}

// New creates a new Fail2Ban.
func New(rules rules.RulesTransformed, allowList ipchecking.NetIPs) *Fail2Ban {
	return &Fail2Ban{
		rules:     rules,
		IPs:       make(map[string]ipchecking.IPViewed),
		allowList: allowList,
	}
}

// ShouldAllow check if the request should be allowed.
// Called when a request was DENIED - increments the denied counter.
func (u *Fail2Ban) ShouldAllow(remoteIP string) bool {
	if u.allowList != nil && u.allowList.Contains(remoteIP) {
		return true
	}

	u.MuIP.Lock()
	defer u.MuIP.Unlock()

	ip, foundIP := u.IPs[remoteIP]

	// Fail2Ban
	if !foundIP {
		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  1,
		}

		fmt.Printf("welcome %q", remoteIP)

		return true
	}

	if ip.Denied {
		if utime.Now().Before(ip.Viewed.Add(u.rules.Bantime)) {
			u.IPs[remoteIP] = ipchecking.IPViewed{
				Viewed: ip.Viewed,
				Count:  ip.Count + 1,
				Denied: true,
			}

			fmt.Printf("%q is still banned since %q, %d request",
				remoteIP, ip.Viewed.Format(time.RFC3339), ip.Count+1)

			return false
		}

		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  1,
			Denied: false,
		}

		fmt.Println(remoteIP + " is no longer banned")

		return true
	}

	if utime.Now().Before(ip.Viewed.Add(u.rules.Findtime)) {
		if ip.Count+1 >= u.rules.MaxRetry {
			u.IPs[remoteIP] = ipchecking.IPViewed{
				Viewed: utime.Now(),
				Count:  ip.Count + 1,
				Denied: true,
			}

			fmt.Printf("%q is banned for %d>=%d request",
				remoteIP, ip.Count+1, u.rules.MaxRetry)

			return false
		}

		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: ip.Viewed,
			Count:  ip.Count + 1,
			Denied: false,
		}

		fmt.Printf("welcome back %q for the %d time", remoteIP, ip.Count+1)

		return true
	}

	u.IPs[remoteIP] = ipchecking.IPViewed{
		Viewed: utime.Now(),
		Count:  1,
		Denied: false,
	}

	fmt.Printf("welcome back %q", remoteIP)

	return true
}

// IsNotBanned Non-incrementing check to see if an IP is already banned.
func (u *Fail2Ban) IsNotBanned(remoteIP string) bool {
	if u.allowList != nil && u.allowList.Contains(remoteIP) {
		return true
	}

	u.MuIP.Lock()
	defer u.MuIP.Unlock()

	ip, foundIP := u.IPs[remoteIP]

	// Fail2Ban
	if !foundIP {
		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  0,
		}

		fmt.Printf("welcome %q", remoteIP)

		return true
	}

	if ip.Denied {
		if utime.Now().Before(ip.Viewed.Add(u.rules.Bantime)) {
			u.IPs[remoteIP] = ipchecking.IPViewed{
				Viewed: utime.Now(), // refresh ban time
				Count:  ip.Count + 1,
				Denied: true,
			}

			fmt.Printf("%q is still banned since %q, %d request",
				remoteIP, ip.Viewed.Format(time.RFC3339), ip.Count+1)

			return false
		}

		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  1,
			Denied: false,
		}

		fmt.Println(remoteIP + " is no longer banned")

		return true
	}

	if utime.Now().Before(ip.Viewed.Add(u.rules.Findtime)) {
		if ip.Count+1 >= u.rules.MaxRetry {
			u.IPs[remoteIP] = ipchecking.IPViewed{
				Viewed: utime.Now(),
				Count:  ip.Count + 1,
				Denied: true,
			}

			fmt.Printf("%q is banned for %d>=%d request",
				remoteIP, ip.Count+1, u.rules.MaxRetry)

			return false
		}

		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: ip.Viewed,
			Count:  ip.Count + 1,
			Denied: false,
		}
		return true
	}

	fmt.Printf("welcome back %q", remoteIP)

	return true
}
