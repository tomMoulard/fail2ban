// Package fail2ban provides a fail2ban implementation.
package fail2ban

import (
	"sync"

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

	if !foundIP {
		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  1,
		}

		return true
	}

	if ip.Denied {
		if utime.Now().Before(ip.Viewed.Add(u.rules.Bantime)) {
			u.IPs[remoteIP] = ipchecking.IPViewed{
				Viewed: ip.Viewed,
				Count:  ip.Count + 1,
				Denied: true,
			}

			return false
		}

		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  1,
			Denied: false,
		}

		return true
	}

	if utime.Now().Before(ip.Viewed.Add(u.rules.Findtime)) {
		if ip.Count+1 >= u.rules.MaxRetry {
			u.IPs[remoteIP] = ipchecking.IPViewed{
				Viewed: utime.Now(),
				Count:  ip.Count + 1,
				Denied: true,
			}

			return false
		}

		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: ip.Viewed,
			Count:  ip.Count + 1,
			Denied: false,
		}

		return true
	}

	u.IPs[remoteIP] = ipchecking.IPViewed{
		Viewed: utime.Now(),
		Count:  1,
		Denied: false,
	}

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

	if !foundIP {
		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  0,
		}

		return true
	}

	if ip.Denied {
		if utime.Now().Before(ip.Viewed.Add(u.rules.Bantime)) {
			u.IPs[remoteIP] = ipchecking.IPViewed{
				Viewed: utime.Now(),
				Count:  ip.Count + 1,
				Denied: true,
			}

			return false
		}

		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  1,
			Denied: false,
		}

		return true
	}

	return true
}
