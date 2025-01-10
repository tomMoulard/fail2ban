// Package fail2ban provides a fail2ban implementation.
package fail2ban

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/cloudflare"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/persistence"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	utime "github.com/tomMoulard/fail2ban/pkg/utils/time"
)

const (
	// CloudflareTimeout is the timeout for Cloudflare API operations.
	CloudflareTimeout = 30 * time.Second
	// PersistenceTimeout is the timeout for persistence operations.
	PersistenceTimeout = 5 * time.Second
)

// Fail2Ban is a fail2ban implementation.
type Fail2Ban struct {
	rules rules.RulesTransformed
	cf    cloudflare.Interface
	store persistence.Store

	MuIP sync.Mutex
	IPs  map[string]ipchecking.IPViewed
}

// New creates a new Fail2Ban.
func New(ctx context.Context, rules rules.RulesTransformed, cf *cloudflare.Client, store persistence.Store) *Fail2Ban {
	fmt.Printf("Plugin: FailToBan is up and running\n")

	f := &Fail2Ban{
		rules: rules,
		cf:    cf,
		store: store,
		IPs:   make(map[string]ipchecking.IPViewed),
	}

	// Start cleanup immediately to handle any expired blocks
	go func() {
		cleanupCtx, cancel := context.WithTimeout(ctx, CloudflareTimeout)
		defer cancel()
		f.cleanupBlockedIPs(cleanupCtx)
	}()

	// Then start the regular cleanup routine
	f.StartCleanup(ctx)

	return f
}

// ShouldAllow check if the request should be allowed.
func (u *Fail2Ban) ShouldAllow(parentCtx context.Context, remoteIP string) bool {
	// First check with a short lock
	u.MuIP.Lock()
	ip, foundIP := u.IPs[remoteIP]
	if !foundIP {
		// New IP - add it and return quickly
		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  1,
		}
		u.MuIP.Unlock()
		fmt.Printf("welcome %q\n", remoteIP)
		return true
	}

	// Check if already denied
	if ip.Denied {
		denied := utime.Now().Before(ip.Viewed.Add(u.rules.Bantime))
		if denied {
			// Update count and return quickly
			newIP := ipchecking.IPViewed{
				Viewed: ip.Viewed,
				Count:  ip.Count + 1,
				Denied: true,
				RuleID: ip.RuleID,
			}
			u.IPs[remoteIP] = newIP
			u.MuIP.Unlock()

			fmt.Printf("%q is still banned since %q, %d request\n",
				remoteIP, ip.Viewed.Format(time.RFC3339), ip.Count+1)
			return false
		}

		// Ban expired - clean up without holding the lock
		delete(u.IPs, remoteIP)
		u.MuIP.Unlock()

		go func() {
			cleanupCtx, cancel := context.WithTimeout(parentCtx, CloudflareTimeout)
			defer cancel()
			u.removeExpiredBlock(cleanupCtx, remoteIP)
		}()

		// Reacquire lock to add new entry
		u.MuIP.Lock()
		u.IPs[remoteIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  1,
			Denied: false,
		}
		u.MuIP.Unlock()

		fmt.Println(remoteIP + " is no longer banned")
		return true
	}

	// Handle normal request counting
	if utime.Now().Before(ip.Viewed.Add(u.rules.Findtime)) {
		// Release lock before potentially expensive operation
		u.MuIP.Unlock()
		return u.handleFindtimeExceeded(parentCtx, remoteIP, ip)
	}

	// Reset count for new findtime window
	u.IPs[remoteIP] = ipchecking.IPViewed{
		Viewed: utime.Now(),
		Count:  1,
		Denied: false,
	}
	u.MuIP.Unlock()

	fmt.Printf("welcome back %q\n", remoteIP)
	return true
}

func (u *Fail2Ban) incrementIPCount(remoteIP string, ip ipchecking.IPViewed) {
	newIP := ipchecking.IPViewed{
		Viewed: ip.Viewed,
		Count:  ip.Count + 1,
		Denied: false,
	}
	u.IPs[remoteIP] = newIP

	fmt.Printf("welcome back %q for the %d time\n", remoteIP, ip.Count+1)
}

func (u *Fail2Ban) handleCloudflareBlock(ctx context.Context, remoteIP string) (string, error) {
	if u.cf == nil {
		return "", nil
	}

	// Create a context with timeout for the block operation
	blockCtx, cancel := context.WithTimeout(ctx, CloudflareTimeout)
	defer cancel()

	ruleID, err := u.cf.BlockIP(blockCtx, remoteIP, u.rules.Bantime)
	if err != nil {
		fmt.Printf("[Fail2Ban] Failed to block IP %s in Cloudflare: %v\n", remoteIP, err)

		return "", fmt.Errorf("failed to block IP in Cloudflare: %w", err)
	}

	fmt.Printf("[Fail2Ban] Successfully blocked IP %s in Cloudflare with rule ID %s\n", remoteIP, ruleID)

	return ruleID, nil
}

func (u *Fail2Ban) persistBlockedIP(ctx context.Context, remoteIP string, viewed ipchecking.IPViewed) {
	if u.store == nil {
		return
	}

	block := persistence.BlockedIP{
		IP:       remoteIP,
		BannedAt: viewed.Viewed,
		BanUntil: viewed.Viewed.Add(u.rules.Bantime),
		RuleID:   viewed.RuleID,
	}

	if err := u.store.AddIP(ctx, block); err != nil {
		fmt.Printf("[Fail2Ban] Failed to persist block for IP %s: %v\n", remoteIP, err)
	}
}

func (u *Fail2Ban) handleFindtimeExceeded(parentCtx context.Context, remoteIP string, ip ipchecking.IPViewed) bool {
	if ip.Count+1 >= u.rules.MaxRetry {
		fmt.Printf("[Fail2Ban] IP %s exceeded retry limit, blocking...\n", remoteIP)

		u.MuIP.Lock()
		// Create the block record
		viewed := ipchecking.IPViewed{
			Viewed: ip.Viewed,
			Count:  ip.Count + 1,
			Denied: true,
		}

		// Store in memory
		u.IPs[remoteIP] = viewed
		u.MuIP.Unlock()

		// Handle Cloudflare and persistence asynchronously
		go func() {
			// Handle Cloudflare
			blockCtx, cancel := context.WithTimeout(context.Background(), CloudflareTimeout)
			ruleID, err := u.handleCloudflareBlock(blockCtx, remoteIP)
			cancel()

			if err != nil {
				fmt.Printf("[Fail2Ban] Error blocking IP in Cloudflare: %v\n", err)
			} else {
				// Update memory with the rule ID
				u.MuIP.Lock()
				if v, exists := u.IPs[remoteIP]; exists && v.Denied {
					v.RuleID = ruleID
					u.IPs[remoteIP] = v
				}
				u.MuIP.Unlock()

				// Handle persistence after Cloudflare success
				persistCtx, cancel := context.WithTimeout(context.Background(), PersistenceTimeout)
				u.persistBlockedIP(persistCtx, remoteIP, viewed)
				cancel()
			}
		}()

		fmt.Printf("%q is banned for %d>=%d request\n", remoteIP, ip.Count+1, u.rules.MaxRetry)

		return false
	}

	u.MuIP.Lock()
	u.incrementIPCount(remoteIP, ip)
	u.MuIP.Unlock()

	return true
}

// RestoreBlock restores a previously blocked IP.
func (u *Fail2Ban) RestoreBlock(ctx context.Context, ip string, bannedAt, banUntil time.Time, ruleID string) {
	u.MuIP.Lock()
	defer u.MuIP.Unlock()

	// Skip if the ban end time is zero (invalid)
	if banUntil.IsZero() {
		fmt.Printf("[Fail2Ban] Skipping restore for IP %s - invalid ban end time\n", ip)

		return
	}

	if utime.Now().After(banUntil) {
		fmt.Printf("[Fail2Ban] Not restoring expired block for IP %s (expired at %s)\n",
			ip, banUntil.Format(time.RFC3339))

		// Just remove from persistence and Cloudflare, but don't add to IPs map
		go func(ctx context.Context) {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), CloudflareTimeout)
			defer cancel()

			u.cleanupExpiredBlock(cleanupCtx, ip)
		}(context.Background())

		return
	}

	// Check if this IP is already in our map
	if existing, exists := u.IPs[ip]; exists {
		// If we already have a longer ban, keep that one
		existingBanUntil := existing.Viewed.Add(u.rules.Bantime)
		if existingBanUntil.After(banUntil) {
			fmt.Printf("[Fail2Ban] Keeping longer block for IP %s (until: %s)\n",
				ip, existingBanUntil.Format(time.RFC3339))

			return
		}
	}

	u.IPs[ip] = ipchecking.IPViewed{
		Viewed: banUntil.Add(-u.rules.Bantime), // Calculate start time from end time
		Count:  1,
		Denied: true,
		RuleID: ruleID,
	}

	fmt.Printf("Restored block for IP %s until %s\n", ip, banUntil)
}

// RangeBlocks iterates over all blocked IPs and calls the provided function for each one.
func (u *Fail2Ban) RangeBlocks(fn func(ip string, bannedAt time.Time, banUntil time.Time, ruleID string)) {
	u.MuIP.Lock()
	defer u.MuIP.Unlock()

	for ip, viewed := range u.IPs {
		if viewed.Denied {
			fn(ip, viewed.Viewed, viewed.Viewed.Add(u.rules.Bantime), viewed.RuleID)
		}
	}
}

// StartCleanup starts the cleanup goroutine.
func (u *Fail2Ban) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				u.cleanupBlockedIPs(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (u *Fail2Ban) cleanupBlockedIPs(parentCtx context.Context) {
	now := time.Now()

	// First collect IPs to cleanup
	var toCleanup []string

	// Lock while reading and modifying memory
	u.MuIP.Lock()
	for ip, viewed := range u.IPs {
		// Skip if the ban time is zero (invalid)
		if viewed.Viewed.IsZero() {
			continue
		}

		banUntil := viewed.Viewed.Add(u.rules.Bantime)
		if viewed.Denied && now.After(banUntil) {
			fmt.Printf("[Fail2Ban] Cleaning up expired block for IP %s (banned at: %s)\n",
				ip, viewed.Viewed.Format(time.RFC3339))

			toCleanup = append(toCleanup, ip)
			delete(u.IPs, ip) // Remove from memory immediately
		}
	}
	u.MuIP.Unlock()

	// Then clean up Cloudflare and persistence without holding the lock
	for _, ip := range toCleanup {
		cleanupCtx, cancel := context.WithTimeout(parentCtx, CloudflareTimeout)
		u.removeExpiredBlock(cleanupCtx, ip)
		cancel()
	}
}

func (u *Fail2Ban) removeExpiredBlock(ctx context.Context, ip string) {
	u.cleanupExpiredBlock(ctx, ip)
}

func (u *Fail2Ban) cleanupExpiredBlock(ctx context.Context, ip string) {
	cleanupCtx, cancel := context.WithTimeout(ctx, CloudflareTimeout)
	defer cancel()

	// Get the rule ID before removing from memory
	var ruleID string
	if viewed, ok := u.IPs[ip]; ok {
		ruleID = viewed.RuleID
	}

	if u.cf != nil {
		if err := u.cf.UnblockIP(cleanupCtx, ip); err != nil {
			fmt.Printf("Failed to unblock IP %s from Cloudflare: %v", ip, err)
		}
	}

	if u.store != nil {
		u.cleanupPersistence(cleanupCtx, ip, ruleID)
	}
}

func (u *Fail2Ban) cleanupPersistence(ctx context.Context, ip, ruleID string) {
	if ruleID != "" {
		if err := u.store.RemoveByRuleID(ctx, ruleID); err != nil && !os.IsNotExist(err) {
			fmt.Printf("Failed to remove IP %s (rule ID: %s) from persistence: %v", ip, ruleID, err)
		}

		return
	}

	// Fallback to removing by IP
	if err := u.store.RemoveIP(ctx, ip); err != nil && !os.IsNotExist(err) {
		fmt.Printf("Failed to remove IP %s from persistence: %v", ip, err)
	}
}
