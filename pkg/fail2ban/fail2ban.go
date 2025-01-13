// Package fail2ban provides a fail2ban implementation.
package fail2ban

import (
	"fmt"
	"sync"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/notifications"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	utime "github.com/tomMoulard/fail2ban/pkg/utils/time"
)

// Fail2Ban is a fail2ban implementation.
type Fail2Ban struct {
	rules    rules.RulesTransformed
	notifSrv *notifications.Service
	MuIP     sync.Mutex
	IPs      map[string]ipchecking.IPViewed
}

// New creates a new Fail2Ban.
func New(rules rules.RulesTransformed, notifSrv *notifications.Service) *Fail2Ban {
	return &Fail2Ban{
		rules:    rules,
		notifSrv: notifSrv,
		IPs:      make(map[string]ipchecking.IPViewed),
	}
}

// ShouldAllow check if the request should be allowed.
func (u *Fail2Ban) ShouldAllow(remoteIP string) bool {
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
		u.notify(notifications.UnbanEvent(remoteIP, fmt.Sprintf("%q is no longer banned", remoteIP)))

		return true
	}

	if utime.Now().Before(ip.Viewed.Add(u.rules.Findtime)) {
		if ip.Count+1 >= u.rules.MaxRetry {
			u.IPs[remoteIP] = ipchecking.IPViewed{
				Viewed: utime.Now(),
				Count:  ip.Count + 1,
				Denied: true,
			}
			msg := fmt.Sprintf("%q is banned for %d>=%d request",
				remoteIP, ip.Count+1, u.rules.MaxRetry)
			fmt.Printf("%s", msg)
			u.notify(notifications.BanEvent(remoteIP, msg, u.rules.Bantime))

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

func (u *Fail2Ban) notify(event notifications.Event) {
	if u.notifSrv == nil {
		return
	}

	u.notifSrv.Notify(event)
}
