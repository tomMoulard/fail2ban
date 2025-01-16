// Package fail2ban provides a fail2ban implementation.
package fail2ban

import (
	"context"
	"fmt"
	"net"
	"strings"
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
	// PeriodicSaveInterval is how often we save the full block list.
	PeriodicSaveInterval = 5 * time.Minute
)

// Fail2Ban is a fail2ban implementation.
type Fail2Ban struct {
	rules rules.RulesTransformed
	cf    cloudflare.Interface
	store persistence.Store

	MuIP sync.Mutex
	IPs  map[string]ipchecking.IPViewed
	// Map to track Cloudflare rule IDs by IP
	ruleIDs map[string]string
}

// New creates a new Fail2Ban.
func New(ctx context.Context, rules rules.RulesTransformed, cf *cloudflare.Client, store persistence.Store) *Fail2Ban {
	fmt.Printf("Plugin: FailToBan is up and running\n")

	f := &Fail2Ban{
		rules:   rules,
		cf:      cf,
		store:   store,
		IPs:     make(map[string]ipchecking.IPViewed),
		ruleIDs: make(map[string]string),
	}

	// Load persisted blocks first.
	if store != nil {
		if blocks, err := store.Load(ctx); err != nil {
			fmt.Printf("[Fail2Ban] Failed to load persisted blocks: %v\n", err)
		} else {
			fmt.Printf("[Fail2Ban] Loaded %d blocks from persistence\n", len(blocks))

			for _, block := range blocks {
				// Only restore if not expired
				if time.Now().Before(block.BanUntil) {
					f.RestoreBlock(ctx, block.IP, block.BannedAt, block.BanUntil, block.RuleID)
				} else {
					fmt.Printf("[Fail2Ban] Skipping expired block for IP %s (expired at %s)\n",
						block.IP, block.BanUntil.Format(time.RFC3339))
				}
			}
		}
	}

	// Start cleanup immediately to handle any expired blocks.
	go func() {
		cleanupCtx, cancel := context.WithTimeout(ctx, CloudflareTimeout)
		defer cancel()
		f.cleanupBlockedIPs(cleanupCtx)
	}()

	// Start the regular cleanup routine.
	f.StartCleanup(ctx)

	// Start periodic saving.
	f.startPeriodicSave(ctx)

	// Start persistence verification.
	go f.verifyPersistence(ctx)

	return f
}

// normalizeIP converts an IP address string to its canonical form.
func normalizeIP(ip string) string {
	// First remove any port number
	ipStr := strings.Split(ip, ":")[0]

	// Handle Cloudflare's IPv6 format with zeros
	if strings.Contains(ipStr, "0000") {
		ipStr = strings.ReplaceAll(ipStr, "0000", "0")
	}

	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return ip // Return original if parsing fails
	}

	// If it's an IPv6 address, return the normalized form
	if v6 := parsed.To16(); v6 != nil && strings.Contains(ip, ":") {
		// Convert to compressed format (::)
		compressed := v6.String()

		// If we're dealing with Cloudflare's format, maintain the full format
		if strings.Contains(ip, "0000") {
			// Convert back to full format with zeros
			parts := strings.Split(compressed, ":")

			var fullParts []string

			for _, part := range parts {
				if part == "" {
					// Expand :: to appropriate number of zero groups
					missing := 8 - (len(parts) - 1)
					for i := 0; i < missing; i++ {
						fullParts = append(fullParts, "0000")
					}
				} else {
					// Pad each part to 4 digits
					fullParts = append(fullParts, fmt.Sprintf("%04s", part))
				}
			}

			return strings.Join(fullParts, ":")
		}

		return compressed
	}

	// For IPv4 or invalid addresses, return as-is
	return ip
}

// ShouldAllow check if the request should be allowed.
func (u *Fail2Ban) ShouldAllow(parentCtx context.Context, remoteIP string) bool {
	normalizedIP := normalizeIP(remoteIP)

	u.MuIP.Lock()

	ip, foundIP := u.IPs[normalizedIP]
	if !foundIP {
		u.IPs[normalizedIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  1,
		}
		u.MuIP.Unlock()

		fmt.Printf("welcome %q\n", normalizedIP)

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
			u.IPs[normalizedIP] = newIP
			u.MuIP.Unlock()

			fmt.Printf("%q is still banned since %q, %d request\n",
				normalizedIP, ip.Viewed.Format(time.RFC3339), ip.Count+1)

			return false
		}

		// Ban expired - clean up without holding the lock
		delete(u.IPs, normalizedIP)
		u.MuIP.Unlock()

		go func() {
			cleanupCtx, cancel := context.WithTimeout(parentCtx, CloudflareTimeout)
			defer cancel()
			u.cleanupBlockedIPs(cleanupCtx)
		}()

		// Reacquire lock to add new entry
		u.MuIP.Lock()
		u.IPs[normalizedIP] = ipchecking.IPViewed{
			Viewed: utime.Now(),
			Count:  1,
			Denied: false,
		}

		u.MuIP.Unlock()

		fmt.Println(normalizedIP + " is no longer banned")

		return true
	}

	// Handle normal request counting
	if utime.Now().Before(ip.Viewed.Add(u.rules.Findtime)) {
		// Release lock before potentially expensive operation
		u.MuIP.Unlock()

		return u.handleFindtimeExceeded(parentCtx, normalizedIP, ip)
	}

	// Reset count for new findtime window
	u.IPs[normalizedIP] = ipchecking.IPViewed{
		Viewed: utime.Now(),
		Count:  1,
		Denied: false,
	}
	u.MuIP.Unlock()

	fmt.Printf("welcome back %q\n", normalizedIP)

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
		viewed := ipchecking.IPViewed{
			Viewed: ip.Viewed,
			Count:  ip.Count + 1,
			Denied: true,
		}
		u.IPs[remoteIP] = viewed
		u.MuIP.Unlock()

		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("[Fail2Ban] Recovered from panic in blocking goroutine: %v\n", r)
				}
			}()

			// Handle Cloudflare block
			blockCtx, cancel := context.WithTimeout(context.Background(), CloudflareTimeout)

			ruleID, err := u.handleCloudflareBlock(blockCtx, remoteIP)

			cancel()

			if err != nil {
				fmt.Printf("[Fail2Ban] Error blocking IP in Cloudflare: %v\n", err)
			} else {
				u.MuIP.Lock()
				if v, exists := u.IPs[remoteIP]; exists && v.Denied {
					v.RuleID = ruleID
					u.IPs[remoteIP] = v
					u.ruleIDs[remoteIP] = ruleID
				}
				u.MuIP.Unlock()
			}

			// Always persist the block, even if Cloudflare fails
			persistCtx, cancel := context.WithTimeout(context.Background(), PersistenceTimeout*2)

			defer cancel()

			fmt.Printf("[Fail2Ban] Store is nil: %v\n", u.store == nil)

			if u.store != nil {
				block := persistence.BlockedIP{
					IP:       remoteIP,
					BannedAt: viewed.Viewed,
					BanUntil: viewed.Viewed.Add(u.rules.Bantime),
					RuleID:   ruleID,
				}

				fmt.Printf("[Fail2Ban] Attempting to persist block for IP %s\n", remoteIP)
				// Load existing blocks
				blocks, err := u.store.Load(persistCtx)
				if err != nil {
					fmt.Printf("[Fail2Ban] Failed to load blocks: %v\n", err)

					return
				}

				// Filter out expired blocks and any existing block for this IP
				now := time.Now()

				var validBlocks []persistence.BlockedIP

				for _, b := range blocks {
					if now.Before(b.BanUntil) && b.IP != remoteIP {
						validBlocks = append(validBlocks, b)
					}
				}

				// Add the new block
				validBlocks = append(validBlocks, block)

				fmt.Printf("[Fail2Ban] Saving %d blocks (including new block)\n", len(validBlocks))

				if err := u.store.Save(persistCtx, validBlocks); err != nil {
					fmt.Printf("[Fail2Ban] Failed to save blocks: %v\n", err)
				}
			}
		}()

		return false
	}

	u.MuIP.Lock()
	u.incrementIPCount(remoteIP, ip)
	u.MuIP.Unlock()

	return true
}

// Add this method to periodically verify persistence.
func (u *Fail2Ban) verifyPersistence(ctx context.Context) {
	if u.store == nil {
		return
	}

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			blocks, err := u.store.Load(ctx)

			if err != nil {
				fmt.Printf("[Fail2Ban] Failed to load blocks during verification: %v\n", err)

				continue
			}

			fmt.Printf("[Fail2Ban] Persistence verification: found %d blocks\n", len(blocks))

			// Filter out expired blocks from persistence
			now := time.Now()

			var validBlocks []persistence.BlockedIP

			for _, block := range blocks {
				if now.Before(block.BanUntil) {
					validBlocks = append(validBlocks, block)
				} else {
					fmt.Printf("[Persistence] Removing expired block for IP %s (expired at %s)\n",
						block.IP, block.BanUntil.Format(time.RFC3339))
				}
			}

			// Get current blocks from memory
			u.MuIP.Lock()
			// Only keep blocks that are still in memory and not expired
			var finalBlocks []persistence.BlockedIP

			for _, block := range validBlocks {
				if viewed, exists := u.IPs[block.IP]; exists && viewed.Denied {
					finalBlocks = append(finalBlocks, block)
				}
			}
			u.MuIP.Unlock()

			if err := u.store.Save(ctx, finalBlocks); err != nil {
				fmt.Printf("[Fail2Ban] Failed to save blocks during verification: %v\n", err)
			}
		case <-ctx.Done():
			return
		}
	}
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

		// Clean up expired block
		go func(ctx context.Context) {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), CloudflareTimeout)
			defer cancel()

			// Remove from Cloudflare if needed
			if u.cf != nil && ruleID != "" {
				if err := u.cf.UnblockByRuleID(cleanupCtx, ruleID); err != nil {
					fmt.Printf("[Cloudflare] Failed to unblock rule ID %s: %v\n", ruleID, err)
				} else {
					fmt.Printf("[Cloudflare] Successfully unblocked IP %s (rule ID: %s)\n", ip, ruleID)
				}
			}

			// Remove from persistence if needed
			if u.store != nil {
				if err := u.store.RemoveIP(cleanupCtx, ip); err != nil {
					fmt.Printf("[Persistence] Failed to remove IP %s: %v\n", ip, err)
				}
			}
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
	if ruleID != "" {
		u.ruleIDs[ip] = ruleID
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
		}
	}
	u.MuIP.Unlock()

	// Load current blocks from persistence
	var currentBlocks []persistence.BlockedIP

	if u.store != nil {
		blocks, err := u.store.Load(parentCtx)
		if err != nil {
			fmt.Printf("[Fail2Ban] Failed to load blocks during cleanup: %v\n", err)
		} else {
			currentBlocks = blocks
		}
	}

	// Then clean up Cloudflare and persistence without holding the lock
	for _, ip := range toCleanup {
		cleanupCtx, cancel := context.WithTimeout(parentCtx, CloudflareTimeout)
		// First remove from Cloudflare
		if u.cf != nil {
			ruleID := u.ruleIDs[ip]
			if ruleID != "" {
				if err := u.cf.UnblockByRuleID(cleanupCtx, ruleID); err != nil {
					fmt.Printf("[Cloudflare] Failed to unblock rule ID %s: %v\n", ruleID, err)

					cancel()

					continue // Skip removing from persistence if Cloudflare fails
				}

				fmt.Printf("[Cloudflare] Successfully unblocked IP %s (rule ID: %s)\n", ip, ruleID)
			}
		}

		// Then remove from memory
		u.MuIP.Lock()
		delete(u.IPs, ip)
		delete(u.ruleIDs, ip)
		u.MuIP.Unlock()

		cancel()
	}

	// Update persistence with remaining blocks
	if u.store != nil && len(currentBlocks) > 0 {
		var validBlocks []persistence.BlockedIP

		for _, block := range currentBlocks {
			// Keep block if it's not in cleanup list and not expired
			shouldKeep := true

			for _, ip := range toCleanup {
				if block.IP == ip {
					shouldKeep = false

					break
				}
			}

			if shouldKeep && now.Before(block.BanUntil) {
				validBlocks = append(validBlocks, block)
			}
		}

		fmt.Printf("[Fail2Ban] Updating persistence with %d remaining blocks\n", len(validBlocks))

		if err := u.store.Save(parentCtx, validBlocks); err != nil {
			fmt.Printf("[Fail2Ban] Failed to update persistence during cleanup: %v\n", err)
		}
	}
}

func (u *Fail2Ban) startPeriodicSave(ctx context.Context) {
	if u.store == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(PeriodicSaveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := u.saveAllBlocks(ctx); err != nil {
					fmt.Printf("[Fail2Ban] Periodic save failed: %v\n", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (u *Fail2Ban) saveAllBlocks(ctx context.Context) error {
	if u.store == nil {
		return nil
	}

	var blocks []persistence.BlockedIP

	u.MuIP.Lock()
	for ip, viewed := range u.IPs {
		if viewed.Denied {
			blocks = append(blocks, persistence.BlockedIP{
				IP:       ip,
				BannedAt: viewed.Viewed,
				BanUntil: viewed.Viewed.Add(u.rules.Bantime),
				RuleID:   viewed.RuleID,
			})
		}
	}
	u.MuIP.Unlock()

	fmt.Printf("[Fail2Ban] Saving %d blocks to persistence\n", len(blocks))

	return u.store.Save(ctx, blocks)
}
