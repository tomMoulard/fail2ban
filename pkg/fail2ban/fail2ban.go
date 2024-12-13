// Package fail2ban provides a fail2ban implementation.
package fail2ban

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/cloudflare"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	utime "github.com/tomMoulard/fail2ban/pkg/utils/time"
)

// Fail2Ban is a fail2ban implementation.
type Fail2Ban struct {
	rules rules.RulesTransformed
	cf    *cloudflare.Client

	MuIP sync.Mutex
	IPs  map[string]ipchecking.IPViewed
}

// New creates a new Fail2Ban.
func New(rules rules.RulesTransformed, cf *cloudflare.Client) *Fail2Ban {
	return &Fail2Ban{
		rules: rules,
		cf:    cf,
		IPs:   make(map[string]ipchecking.IPViewed),
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

		// Unblock in Cloudflare
		if u.cf != nil {
			if err := u.cf.UnblockIP(context.Background(), remoteIP); err != nil {
				log.Printf("failed to unblock IP in Cloudflare: %v", err)
			}
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
		return u.handleFindtimeExceeded(remoteIP, ip)
	}

	u.IPs[remoteIP] = ipchecking.IPViewed{
		Viewed: utime.Now(),
		Count:  1,
		Denied: false,
	}

	fmt.Printf("welcome back %q", remoteIP)

	return true
}

func (u *Fail2Ban) handleFindtimeExceeded(remoteIP string, ip ipchecking.IPViewed) bool {
	if ip.Count+1 >= u.rules.MaxRetry {
		// Block in Cloudflare if enabled
		if u.cf != nil {
			if err := u.cf.BlockIP(context.Background(), remoteIP, u.rules.Bantime); err != nil {
				log.Printf("failed to block IP in Cloudflare: %v", err)
			}
		}

		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: ip.Viewed,
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

// RestoreBlock restores a previously blocked IP.
func (u *Fail2Ban) RestoreBlock(ip string, bannedAt, banUntil time.Time) {
	u.MuIP.Lock()
	defer u.MuIP.Unlock()

	u.IPs[ip] = ipchecking.IPViewed{
		Viewed: bannedAt,
		Count:  u.rules.MaxRetry,
		Denied: true,
	}

	log.Printf("Restored block for IP %s until %s", ip, banUntil)
}

func (u *Fail2Ban) RangeBlocks(fn func(ip string, bannedAt time.Time, banUntil time.Time)) {
	u.MuIP.Lock()
	defer u.MuIP.Unlock()

	for ip, viewed := range u.IPs {
		if viewed.Denied {
			fn(ip, viewed.Viewed, viewed.Viewed.Add(u.rules.Bantime))
		}
	}
}
