// Package cloudflare provides a client to interact with the Cloudflare API.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/persistence"
)

type Client struct {
	apiToken    string
	zoneID      string
	baseURL     string
	maxRetries  int
	retryDelay  time.Duration
	blockedIPs  sync.Map // map[string]time.Time
	stopCleanup chan struct{}
	workQueue   chan func() // Add work queue for async operations
}

func NewClient(ctx context.Context, apiToken, zoneID string, maxRetries int, retryDelay time.Duration) *Client {
	log.Printf("[Cloudflare] Initializing client with maxRetries=%d, retryDelay=%v", maxRetries, retryDelay)

	const workQueueBufferSize = 100

	c := &Client{
		apiToken:    apiToken,
		zoneID:      zoneID,
		baseURL:     "https://api.cloudflare.com/client/v4",
		maxRetries:  maxRetries,
		retryDelay:  retryDelay,
		stopCleanup: make(chan struct{}),
		workQueue:   make(chan func(), workQueueBufferSize), // Buffer size for async operations
	}

	// Start worker goroutine to process API calls
	go c.processWorkQueue(ctx)

	go c.cleanupBlockedIPs(ctx)
	log.Printf("[Cloudflare] Starting cleanup goroutine with interval=%v, timeout=%v", CleanupInterval, CleanupTimeout)

	return c
}

const (
	CleanupInterval = 1 * time.Minute
	CleanupTimeout  = 10 * time.Second
	MaxBanTimeout   = 24 * time.Hour
)

func (c *Client) processWorkQueue(ctx context.Context) {
	for {
		select {
		case work := <-c.workQueue:
			work()
		case <-ctx.Done():
			return
		case <-c.stopCleanup:
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
			log.Printf("[Cloudflare] Running cleanup check")

			blocked := 0
			unblocked := 0

			c.blockedIPs.Range(func(key, value interface{}) bool {
				select {
				case <-ctx.Done():
					return false
				default:
					ip, ok := key.(string)
					if !ok {
						log.Printf("[Cloudflare] Invalid key type in blockedIPs: %T", key)

						return true
					}

					banUntil, ok := value.(time.Time)
					if !ok {
						log.Printf("[Cloudflare] Invalid value type in blockedIPs for IP %s: %T", ip, value)

						return true
					}

					blocked++
					timeLeft := time.Until(banUntil)
					log.Printf("[Cloudflare] Checking IP %s - ban expires in %v", ip, timeLeft.Round(time.Second))

					if time.Now().After(banUntil) {
						log.Printf("[Cloudflare] Unblocking IP %s (ban expired)", ip)

						// Remove from local map before queueing the unblock
						c.blockedIPs.Delete(ip)

						unblocked++

						// Queue the unblock operation with a new background context
						cleanupCtx := ctx
						c.workQueue <- func() {
							// Create a new context for the unblock operation
							unblockCtx, cancel := context.WithTimeout(cleanupCtx, CleanupTimeout)
							defer cancel()

							if err := c.UnblockIP(unblockCtx, ip); err != nil {
								log.Printf("[Cloudflare] Failed to unblock IP %s: %v", ip, err)

								return
							}

							log.Printf("[Cloudflare] Successfully unblocked IP %s", ip)
						}
					}

					return true
				}
			})

			log.Printf("[Cloudflare] Cleanup complete - checked %d IPs, scheduled %d for unblock",
				blocked, unblocked)

		case <-c.stopCleanup:
			log.Printf("[Cloudflare] Cleanup goroutine stopped")

			return

		case <-ctx.Done():
			log.Printf("[Cloudflare] Cleanup goroutine canceled: %v", ctx.Err())

			return
		}
	}
}

func (c *Client) Close() {
	log.Printf("[Cloudflare] Shutting down client")

	if c.stopCleanup != nil {
		close(c.stopCleanup)
	}
}

type AccessRule struct {
	Mode          string `json:"mode"`
	Configuration struct {
		Target string `json:"target"`
		Value  string `json:"value"`
	} `json:"configuration"`
	Notes string `json:"notes"`
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
			log.Printf("[Cloudflare] Rate limit remaining: %s", rl)
		}

		// Don't retry on client errors (4xx) except rate limits
		const HTTPTooManyRequests = 429
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			if resp.StatusCode == HTTPTooManyRequests {
				if err := resp.Body.Close(); err != nil {
					log.Printf("[Cloudflare] Failed to close response body: %v", err)
				}

				lastErr = errors.New("rate limited")

				continue
			}

			return resp, nil
		}

		// Retry on server errors (5xx)
		if resp.StatusCode >= http.StatusInternalServerError {
			if err := resp.Body.Close(); err != nil {
				log.Printf("[Cloudflare] Failed to close response body: %v", err)
			}

			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)

			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func (c *Client) checkResponse(resp *http.Response) error {
	var cfResp CloudflareResponse

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Try to decode as JSON first
	if err := json.Unmarshal(body, &cfResp); err != nil {
		// If we got HTML instead of JSON, there might be an issue with authentication or headers
		if strings.Contains(string(body), "<html>") {
			log.Printf("[Cloudflare] Received HTML response instead of JSON. This usually indicates an authentication issue or missing headers")
			log.Printf("[Cloudflare] Please verify:\n" +
				"1. API Token permissions (Zone > Firewall Services > Edit)\n" +
				"2. Zone ID is correct\n" +
				"3. API Token is valid")
		}

		return fmt.Errorf("failed to decode response (status %d): %w\nBody: %s",
			resp.StatusCode, err, string(body))
	}

	if !cfResp.Success {
		return fmt.Errorf("cloudflare API error (status %d): %v\nBody: %s",
			resp.StatusCode, cfResp.Errors, string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Add helper function to redact sensitive headers.
func redactHeaders(headers http.Header) http.Header {
	redacted := headers.Clone()
	if auth := redacted.Get("Authorization"); auth != "" {
		redacted.Set("Authorization", "Bearer [REDACTED]")
	}

	return redacted
}

func (c *Client) BlockIP(ctx context.Context, ip string, banDuration time.Duration) error {
	// Store in local map immediately
	c.blockedIPs.Store(ip, time.Now().Add(banDuration))

	// Queue the API call
	c.workQueue <- func() {
		rule := AccessRule{
			Mode: "block",
			Configuration: struct {
				Target string `json:"target"`
				Value  string `json:"value"`
			}{
				Target: "ip",
				Value:  ip,
			},
			Notes: fmt.Sprintf("Blocked by Traefik fail2ban plugin (duration: %s)", banDuration),
		}

		body, err := json.Marshal(rule)
		if err != nil {
			log.Printf("[Cloudflare] Failed to marshal rule: %v", err)

			return
		}

		log.Printf("[Cloudflare] Sending block request: %s", string(body))

		req, err := http.NewRequestWithContext(ctx,
			http.MethodPost,
			fmt.Sprintf("%s/zones/%s/firewall/access_rules/rules", c.baseURL, c.zoneID),
			bytes.NewReader(body))
		if err != nil {
			log.Printf("[Cloudflare] Failed to create request: %v", err)

			return
		}

		// Add all required headers
		req.Header.Set("Authorization", "Bearer "+c.apiToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "traefik-fail2ban/1.0")

		// Log request details with redacted headers
		log.Printf("[Cloudflare] Making request to %s with headers: %v", req.URL, redactHeaders(req.Header))

		resp, err := c.doWithRetry(ctx, req)
		if err != nil {
			log.Printf("[Cloudflare] Failed to execute request: %v", err)

			return
		}

		defer func() {
			if err := resp.Body.Close(); err != nil {
				log.Printf("[Cloudflare] Failed to close response body: %v", err)
			}
		}()

		// Log response headers with redacted information
		log.Printf("[Cloudflare] Response status: %s, headers: %v", resp.Status, redactHeaders(resp.Header))

		if err := c.checkResponse(resp); err != nil {
			log.Printf("[Cloudflare] API request failed: %v", err)

			// Check if token is valid
			if resp.StatusCode == http.StatusUnauthorized {
				log.Printf("[Cloudflare] Authentication failed. Please check your API token permissions. " +
					"Required permissions: Zone:Firewall Services:Edit")
			}
		}
	}

	return nil
}

func (c *Client) UnblockIP(ctx context.Context, ip string) error {
	log.Printf("[Cloudflare] Starting unblock process for IP %s", ip)

	// First get the rule ID for this IP
	req, err := http.NewRequestWithContext(ctx,
		http.MethodGet,
		fmt.Sprintf("%s/zones/%s/firewall/access_rules/rules?configuration.target=ip&configuration.value=%s",
			c.baseURL, c.zoneID, ip),
		nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	var result struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("[Cloudflare] Failed to close response body: %v", closeErr)
		}

		return fmt.Errorf("failed to decode response: %w", err)
	}

	if err := resp.Body.Close(); err != nil {
		log.Printf("[Cloudflare] Failed to close response body: %v", err)
	}

	if len(result.Result) == 0 {
		log.Printf("[Cloudflare] No rules found for IP %s", ip)

		return nil
	}

	// Remove each rule found for this IP
	for _, rule := range result.Result {
		log.Printf("[Cloudflare] Removing rule %s for IP %s", rule.ID, ip)

		if err := c.removeFirewallRule(ctx, rule.ID); err != nil {
			return fmt.Errorf("failed to remove rule %s: %w", rule.ID, err)
		}

		log.Printf("[Cloudflare] Successfully removed rule %s for IP %s", rule.ID, ip)
	}

	return nil
}

func (c *Client) LoadExistingBlocks(ctx context.Context) ([]persistence.BlockedIP, error) {
	log.Printf("[Cloudflare] Loading existing blocks")

	req, err := http.NewRequestWithContext(ctx,
		http.MethodGet,
		fmt.Sprintf("%s/zones/%s/firewall/access_rules/rules?configuration.target=ip&mode=block&notes=%s",
			c.baseURL, c.zoneID, url.QueryEscape("Blocked by Traefik fail2ban plugin")),
		nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close response body: %v", err)
		}
	}()

	var result struct {
		Result []struct {
			ID            string    `json:"id"`
			CreatedOn     time.Time `json:"createdOn"`
			ModifiedOn    time.Time `json:"modifiedOn"`
			Configuration struct {
				Value string `json:"value"`
			} `json:"configuration"`
			Notes string `json:"notes"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	blocks := make([]persistence.BlockedIP, 0, len(result.Result))

	for _, rule := range result.Result {
		// Try to extract ban duration from the notes
		banDuration := c.extractBanDuration(rule.Notes)
		if banDuration == 0 {
			log.Printf("[Cloudflare] Could not determine ban duration for IP %s, using default %s",
				rule.Configuration.Value, MaxBanTimeout)

			banDuration = MaxBanTimeout // Default duration if we can't parse it
		}

		// Store in the sync.Map for cleanup
		banUntil := rule.CreatedOn.Add(banDuration)
		if time.Now().After(banUntil) {
			log.Printf("[Cloudflare] IP %s ban has already expired, scheduling immediate cleanup",
				rule.Configuration.Value)

			// Create a closure to capture the rule ID
			ruleID := rule.ID // Capture rule.ID in a new variable

			// Schedule immediate cleanup for expired bans
			c.workQueue <- func() {
				cleanupCtx, cancel := context.WithTimeout(ctx, CleanupTimeout) // Use parent context
				defer cancel()
				if err := c.removeFirewallRule(cleanupCtx, ruleID); err != nil {
					log.Printf("[Cloudflare] Failed to remove expired rule %s: %v", ruleID, err)
				}
			}

			continue
		}

		c.blockedIPs.Store(rule.Configuration.Value, banUntil)
		blocks = append(blocks, persistence.BlockedIP{
			IP:       rule.Configuration.Value,
			BannedAt: rule.CreatedOn,
			BanUntil: banUntil,
		})
	}

	return blocks, nil
}

// Add new helper function to handle rule removal.
func (c *Client) removeFirewallRule(ctx context.Context, ruleID string) error {
	req, err := http.NewRequestWithContext(ctx,
		http.MethodDelete,
		fmt.Sprintf("%s/zones/%s/firewall/access_rules/rules/%s",
			c.baseURL, c.zoneID, ruleID),
		nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("[Cloudflare] Failed to close response body: %v", err)
		}
	}()

	return c.checkResponse(resp)
}

func (c *Client) extractBanDuration(notes string) time.Duration {
	// Extract duration from note format: "Blocked by Traefik fail2ban plugin (duration: 3h0m0s)"
	start := strings.Index(notes, "(duration: ")

	if start == -1 {
		return 0
	}

	start += len("(duration: ")

	end := strings.Index(notes[start:], ")")

	if end == -1 {
		return 0
	}

	durationStr := notes[start : start+end]

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		log.Printf("[Cloudflare] Failed to parse duration %q: %v", durationStr, err)

		return 0
	}

	return duration
}

func (c *Client) RangeBlocks(fn func(ip string, banUntil time.Time)) {
	c.blockedIPs.Range(func(key, value interface{}) bool {
		ip, ok := key.(string)
		if !ok {
			return true
		}

		banUntil, ok := value.(time.Time)
		if !ok {
			return true
		}

		fn(ip, banUntil)

		return true
	})
}
