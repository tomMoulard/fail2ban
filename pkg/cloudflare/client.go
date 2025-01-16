// Package cloudflare provides a client to interact with the Cloudflare API.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/persistence"
	"github.com/tomMoulard/fail2ban/pkg/rules"
)

const (
	CleanupInterval = 1 * time.Minute
	CleanupTimeout  = 10 * time.Second
	MaxBanTimeout   = 24 * time.Hour
	DefaultTimeout  = 10 * time.Second
	BlockQueueSize  = 100
)

type Client struct {
	apiToken    string
	zoneID      string
	baseURL     string
	maxRetries  int
	retryDelay  time.Duration
	blockedIPs  sync.Map // map[string]time.Time
	stopCleanup chan struct{}
	blockQueue  chan blockRequest
	rules       rules.RulesTransformed
}

type blockRequest struct {
	ip          string
	banDuration time.Duration
	resultChan  chan blockResult
}

type blockResult struct {
	ruleID string
	err    error
}

// Interface defines the methods that a Cloudflare client must implement.
type Interface interface {
	BlockIP(ctx context.Context, ip string, banDuration time.Duration) (string, error)
	UnblockIP(ctx context.Context, ip string) error
	UnblockByRuleID(ctx context.Context, ruleID string) error
	LoadExistingBlocks(ctx context.Context) ([]persistence.BlockedIP, error)
	GetBlockedIP(ip string) (interface{}, bool)
	RangeBlocks(fn func(ip string, banUntil time.Time))
	Close()
}

func NewClient(ctx context.Context, apiToken, zoneID string, maxRetries int, retryDelay time.Duration, rules rules.RulesTransformed) *Client {
	fmt.Printf("[Cloudflare] Initializing client with maxRetries=%d, retryDelay=%v\n", maxRetries, retryDelay)

	const queueBufferSize = 100

	c := &Client{
		apiToken:    apiToken,
		zoneID:      zoneID,
		baseURL:     "https://api.cloudflare.com/client/v4",
		maxRetries:  maxRetries,
		retryDelay:  retryDelay,
		stopCleanup: make(chan struct{}),
		blockQueue:  make(chan blockRequest, queueBufferSize),
		rules:       rules,
	}

	// Start worker goroutine to process block requests
	go c.processBlockQueue(ctx)

	go c.cleanupBlockedIPs(ctx)
	fmt.Printf("[Cloudflare] Starting cleanup goroutine with interval=%v, timeout=%v\n", CleanupInterval, CleanupTimeout)

	return c
}

func (c *Client) processBlockQueue(ctx context.Context) {
	for {
		select {
		case req := <-c.blockQueue:
			fmt.Printf("[Cloudflare] Processing block request for IP %s\n", req.ip)

			// Create a new context with timeout for this operation
			timeoutCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
			ruleID, err := c.doBlockIP(timeoutCtx, req.ip, req.banDuration)
			req.resultChan <- blockResult{
				ruleID: ruleID,
				err:    err,
			}
			close(req.resultChan)

			if err != nil {
				fmt.Printf("[Cloudflare] Failed to block IP %s: %v\n", req.ip, err)
			} else {
				fmt.Printf("[Cloudflare] Successfully blocked IP %s with rule ID %s\n", req.ip, ruleID)
				// Store the block in memory
				c.blockedIPs.Store(req.ip, time.Now().Add(req.banDuration))
			}

			cancel()

		case <-ctx.Done():
			fmt.Printf("[Cloudflare] Block queue processor shutting down\n")

			return
		}
	}
}

func (c *Client) cleanupBlockedIPs(ctx context.Context) {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fmt.Printf("[Cloudflare] Running cleanup check\n")

			blocked := 0
			unblocked := 0

			c.blockedIPs.Range(func(key, value interface{}) bool {
				select {
				case <-ctx.Done():
					return false
				default:
					ip, ok := key.(string)
					if !ok {
						fmt.Printf("[Cloudflare] Invalid key type in blockedIPs: %T\n", key)

						return true
					}

					var banUntil time.Time
					switch v := value.(type) {
					case time.Time:
						banUntil = v
					case ipchecking.IPViewed:
						banUntil = v.Viewed.Add(c.rules.Bantime)
					default:
						fmt.Printf("[Cloudflare] Invalid value type in blockedIPs for IP %s: %T\n", ip, value)

						return true
					}

					blocked++
					timeLeft := time.Until(banUntil)
					fmt.Printf("[Cloudflare] Checking IP %s - ban expires in %v\n", ip, timeLeft.Round(time.Second))

					if time.Now().After(banUntil) {
						fmt.Printf("[Cloudflare] Unblocking IP %s (ban expired)\n", ip)

						// Remove from local map before queueing the unblock
						c.blockedIPs.Delete(ip)

						unblocked++

						// Create a new context for the unblock operation
						unblockCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)

						go func(ip string) {
							defer cancel()

							if err := c.UnblockIP(unblockCtx, ip); err != nil {
								fmt.Printf("[Cloudflare] Failed to unblock IP %s: %v\n", ip, err)
							}
						}(ip)
					}

					return true
				}
			})

			fmt.Printf("[Cloudflare] Cleanup complete - checked %d IPs, scheduled %d for unblock\n",
				blocked, unblocked)

		case <-c.stopCleanup:
			fmt.Printf("[Cloudflare] Cleanup goroutine stopped\n")

			return

		case <-ctx.Done():
			fmt.Printf("[Cloudflare] Cleanup goroutine canceled: %v\n", ctx.Err())

			return
		}
	}
}

func (c *Client) Close() {
	fmt.Printf("[Cloudflare] Shutting down client\n")

	if c.stopCleanup != nil {
		close(c.stopCleanup)
	}
}

type AccessRule struct {
	ID            string `json:"id"`
	Configuration struct {
		Target string `json:"target"`
		Value  string `json:"value"`
	} `json:"configuration"`
	Mode      string    `json:"mode"`
	Notes     string    `json:"notes"`
	CreatedOn time.Time `json:"createdOn"`
}

type CloudflareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

type CloudflareResponse struct {
	Success  bool              `json:"success"`
	Errors   []CloudflareError `json:"errors"`
	Result   json.RawMessage   `json:"result"`
	Messages []string          `json:"messages"`
}

func (c *Client) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context canceled: %w", ctx.Err())
			case <-time.After(c.retryDelay):
			}
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err

			continue
		}

		// Log rate limit headers if present
		if rl := resp.Header.Get("Ratelimit-Remaining"); rl != "" {
			fmt.Printf("[Cloudflare] Rate limit remaining: %s\n", rl)
		}

		// Don't retry on client errors (4xx) except rate limits
		const HTTPTooManyRequests = 429
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			if resp.StatusCode == HTTPTooManyRequests {
				if err := resp.Body.Close(); err != nil {
					fmt.Printf("[Cloudflare] Failed to close response body: %v\n", err)
				}

				lastErr = errors.New("rate limited")

				continue
			}

			return resp, nil
		}

		// Retry on server errors (5xx)
		if resp.StatusCode >= http.StatusInternalServerError {
			if err := resp.Body.Close(); err != nil {
				fmt.Printf("[Cloudflare] Failed to close response body: %v\n", err)
			}

			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)

			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func (c *Client) checkResponse(resp *http.Response) (*CloudflareResponse, error) {
	var cfResp CloudflareResponse

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Try to decode as JSON first
	if err := json.Unmarshal(body, &cfResp); err != nil {
		// If we got HTML instead of JSON, there might be an issue with authentication or headers
		if strings.Contains(string(body), "<html>") {
			fmt.Printf("[Cloudflare] Received HTML response instead of JSON. This usually indicates an authentication issue or missing headers\n")
			fmt.Printf("[Cloudflare] Please verify:\n" +
				"1. API Token permissions (Zone > Firewall Services > Edit)\n" +
				"2. Zone ID is correct\n" +
				"3. API Token is valid\n")
		}

		return nil, fmt.Errorf("failed to decode response (status %d): %w\nBody: %s",
			resp.StatusCode, err, string(body))
	}

	if !cfResp.Success {
		return nil, fmt.Errorf("cloudflare API error (status %d): %v\nBody: %s",
			resp.StatusCode, cfResp.Errors, string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	return &cfResp, nil
}

func (c *Client) BlockIP(ctx context.Context, ip string, banDuration time.Duration) (string, error) {
	fmt.Printf("[Cloudflare] Attempting to block IP %s for duration %v\n", ip, banDuration)

	// Check if IP is already blocked
	if _, exists := c.blockedIPs.Load(ip); exists {
		fmt.Printf("[Cloudflare] IP %s is already blocked\n", ip)

		return "", nil
	}

	// Create the access rule directly
	ruleID, err := c.doBlockIP(ctx, ip, banDuration)
	if err != nil {
		return "", fmt.Errorf("failed to create block rule: %w", err)
	}

	// Store in memory after successful API call
	c.blockedIPs.Store(ip, ipchecking.IPViewed{
		Viewed: time.Now(),
		Count:  1,
		Denied: true,
		RuleID: ruleID,
	})

	return ruleID, nil
}

// New helper function to do the actual blocking.
func (c *Client) doBlockIP(ctx context.Context, ip string, banDuration time.Duration) (string, error) {
	fmt.Printf("[Cloudflare] Creating block rule for IP %s (duration: %v)\n", ip, banDuration)

	banUntil := time.Now().Add(banDuration)

	// Create the access rule
	data := map[string]interface{}{
		"mode": "block",
		"configuration": map[string]string{
			"target": "ip",
			"value":  ip,
		},
		"notes": "Blocked by Traefik fail2ban plugin - ban until " + banUntil.Format(time.RFC3339),
	}

	body, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("%s/zones/%s/firewall/access_rules/rules", c.baseURL, c.zoneID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	c.addHeaders(req)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("[Cloudflare] Error closing response body: %v", err)
		}
	}()

	cfResp, err := c.checkResponse(resp)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}

	var result struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(cfResp.Result, &result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Printf("[Cloudflare] Successfully created block rule %s for IP %s\n", result.ID, ip)

	return result.ID, nil
}

// UnblockIP removes an IP from Cloudflare's firewall rules.
func (c *Client) UnblockIP(ctx context.Context, ip string) error {
	// Try to get the rule ID from our local state first
	var ruleID string

	var ipv ipchecking.IPViewed

	if val, _ := c.blockedIPs.Load(ip); val != nil {
		ipv, _ = val.(ipchecking.IPViewed)
		if ipv.RuleID != "" {
			ruleID = ipv.RuleID
		}
	}

	if ruleID == "" {
		// Fallback to listing rules if we don't have the ID cached
		rules, err := c.listRules(ctx)
		if err != nil {
			return fmt.Errorf("failed to list rules: %w", err)
		}

		for _, rule := range rules {
			// Compare both IPs in their canonical form
			ruleIP := net.ParseIP(rule.Configuration.Value)
			targetIP := net.ParseIP(ip)

			if ruleIP != nil && targetIP != nil && ruleIP.Equal(targetIP) {
				ruleID = rule.ID

				break
			}
		}

		if ruleID == "" {
			fmt.Printf("[Cloudflare] No rule found for IP %s", ip)

			return nil
		}
	}

	// Remove from local state before attempting to delete from Cloudflare
	c.blockedIPs.Delete(ip)

	// Delete the rule
	url := fmt.Sprintf("%s/zones/%s/firewall/access_rules/rules/%s",
		c.baseURL, c.zoneID, ruleID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.addHeaders(req)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("[Cloudflare] Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("[Cloudflare] Successfully unblocked IP %s (rule ID: %s)", ip, ruleID)

	return nil
}

// listRules returns all firewall rules.
func (c *Client) listRules(ctx context.Context) ([]AccessRule, error) {
	url := fmt.Sprintf("%s/zones/%s/firewall/access_rules/rules", c.baseURL, c.zoneID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.addHeaders(req)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("[Cloudflare] Error closing response body: %v", err)
		}
	}()

	var result struct {
		Result []AccessRule `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Result, nil
}

func (c *Client) LoadExistingBlocks(ctx context.Context) ([]persistence.BlockedIP, error) {
	fmt.Printf("[Cloudflare] Loading existing blocks\n")

	// Get existing rules
	rules, err := c.listRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	// Pre-allocate blocks slice with estimated capacity
	blocks := make([]persistence.BlockedIP, 0, len(rules))

	for _, rule := range rules {
		// Skip non-fail2ban rules
		if !strings.Contains(rule.Notes, "Blocked by Traefik fail2ban plugin") {
			continue
		}

		banUntil := c.extractBanTime(rule.Notes)
		if banUntil.IsZero() {
			// If we can't parse the ban time, remove the rule
			fmt.Printf("[Cloudflare] Removing rule with invalid ban time: %s\n", rule.ID)

			unblockCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
			err := c.UnblockIP(unblockCtx, rule.Configuration.Value)

			go func(ip string) {
				defer cancel()

				if err != nil {
					fmt.Printf("[Cloudflare] Failed to unblock IP %s: %v\n", ip, err)
				}
			}(rule.Configuration.Value)

			continue
		}

		// Always add to blocks list, even if expired
		blocks = append(blocks, persistence.BlockedIP{
			IP:       rule.Configuration.Value,
			BanUntil: banUntil,
			RuleID:   rule.ID,
		})

		// Only store in memory if the ban hasn't expired
		if time.Now().Before(banUntil) {
			c.blockedIPs.Store(rule.Configuration.Value, ipchecking.IPViewed{
				Viewed: time.Now(),
				Count:  1,
				Denied: true,
				RuleID: rule.ID,
			})
		} else {
			// Remove expired blocks
			unblockCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
			defer cancel()

			if err := c.UnblockIP(unblockCtx, rule.Configuration.Value); err != nil {
				fmt.Printf("[Cloudflare] Failed to unblock expired IP %s: %v\n", rule.Configuration.Value, err)
			}
		}
	}

	fmt.Printf("[Cloudflare] Loaded %d blocks (including expired)\n", len(blocks))

	return blocks, nil
}

func (c *Client) extractBanTime(notes string) time.Time {
	// Extract time from note format: "Blocked by Traefik fail2ban plugin - ban until 2006-01-02T15:04:05Z"
	start := strings.Index(notes, "ban until ")
	if start == -1 {
		return time.Time{}
	}

	// Add 10 to skip over "ban until "
	timeStr := strings.TrimSpace(notes[start+10:])
	t, err := time.Parse(time.RFC3339, timeStr)

	if err != nil {
		fmt.Printf("[Cloudflare] Failed to parse ban time %q: %v\n", timeStr, err)

		return time.Time{}
	}

	return t
}

func (c *Client) RangeBlocks(fn func(ip string, banUntil time.Time)) {
	c.blockedIPs.Range(func(key, value interface{}) bool {
		ip, ok := key.(string)
		if !ok {
			fmt.Printf("[Cloudflare] Invalid key type in blockedIPs: %T\n", key)

			return true
		}

		var banUntil time.Time
		switch v := value.(type) {
		case time.Time:
			banUntil = v
		case ipchecking.IPViewed:
			banUntil = v.Viewed.Add(c.rules.Bantime)
		default:
			fmt.Printf("[Cloudflare] Invalid value type in blockedIPs for IP %s: %T\n", ip, value)

			return true
		}

		fn(ip, banUntil)

		return true
	})
}

// addHeaders adds the required headers for Cloudflare API requests.
func (c *Client) addHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "traefik-fail2ban/1.0")
}

// GetBlockedIP returns the blocked IP information if it exists.
func (c *Client) GetBlockedIP(ip string) (interface{}, bool) {
	return c.blockedIPs.Load(ip)
}

func (c *Client) UnblockByRuleID(ctx context.Context, ruleID string) error {
	if ruleID == "" {
		return nil
	}

	endpoint := fmt.Sprintf("%s/zones/%s/firewall/rules/%s", c.baseURL, c.zoneID, ruleID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
