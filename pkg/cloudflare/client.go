// Package cloudflare provides a client to interact with the Cloudflare API.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
}

func NewClient(ctx context.Context, apiToken, zoneID string, maxRetries int, retryDelay time.Duration) *Client {
	log.Printf("[Cloudflare] Initializing client with maxRetries=%d, retryDelay=%v", maxRetries, retryDelay)

	c := &Client{
		apiToken:    apiToken,
		zoneID:      zoneID,
		baseURL:     "https://api.cloudflare.com/client/v4",
		maxRetries:  maxRetries,
		retryDelay:  retryDelay,
		stopCleanup: make(chan struct{}),
	}

	go c.cleanupBlockedIPs(ctx)
	log.Printf("[Cloudflare] Starting cleanup goroutine with interval=%v, timeout=%v", CleanupInterval, CleanupTimeout)

	return c
}

const (
	CleanupInterval = 1 * time.Minute
	CleanupTimeout  = 10 * time.Second
)

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
				// Create a new context with timeout for each operation
				cleanupCtx, cancel := context.WithTimeout(ctx, CleanupTimeout)
				defer cancel()

				ip, ok := key.(string)
				if !ok {
					log.Printf("invalid key type in blockedIPs: %T", key)

					return true
				}

				banUntil, ok := value.(time.Time)
				if !ok {
					log.Printf("invalid value type in blockedIPs for IP %s: %T", ip, value)

					return true
				}

				blocked++
				timeLeft := time.Until(banUntil)
				log.Printf("[Cloudflare] Checking IP %s - ban expires in %v", ip, timeLeft)

				if time.Now().After(banUntil) {
					log.Printf("[Cloudflare] Unblocking IP %s (ban expired)", ip)

					if err := c.UnblockIP(cleanupCtx, ip); err != nil {
						log.Printf("failed to unblock IP %s in Cloudflare: %v", ip, err)
					}

					c.blockedIPs.Delete(ip)

					unblocked++
				}

				return true
			})

			log.Printf("[Cloudflare] Cleanup complete - checked %d IPs, unblocked %d", blocked, unblocked)

		case <-c.stopCleanup:
			log.Printf("[Cloudflare] Cleanup goroutine stopped")

			return
		case <-ctx.Done():
			log.Printf("[Cloudflare] Cleanup goroutine canceled")

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
}

type CloudflareResponse struct {
	Success bool              `json:"success"`
	Errors  []CloudflareError `json:"errors"`
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

		// Don't retry on client errors (4xx)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return resp, nil
		}

		// Retry on server errors (5xx)
		if resp.StatusCode >= http.StatusInternalServerError {
			if err := resp.Body.Close(); err != nil {
				log.Printf("failed to close response body: %v", err)
			}

			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)

			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func (c *Client) checkResponse(resp *http.Response) error {
	if resp.StatusCode == http.StatusOK {
		var cfResp CloudflareResponse
		if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}

		if !cfResp.Success {
			return fmt.Errorf("cloudflare API error: %v", cfResp.Errors)
		}

		return nil
	}

	return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

func (c *Client) BlockIP(ctx context.Context, ip string, banDuration time.Duration) error {
	log.Printf("[Cloudflare] Blocking IP %s for %v", ip, banDuration)
	c.blockedIPs.Store(ip, time.Now().Add(banDuration))

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
		return fmt.Errorf("failed to marshal rule: %w", err)
	}

	log.Printf("[Cloudflare] Sending block request: %s", string(body))

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost,
		fmt.Sprintf("%s/zones/%s/firewall/access_rules/rules", c.baseURL, c.zoneID),
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close response body: %v", err)
		}
	}()

	return c.checkResponse(resp)
}

func (c *Client) UnblockIP(ctx context.Context, ip string) error {
	log.Printf("[Cloudflare] Attempting to unblock IP %s", ip)

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

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close response body: %v", err)
		}
	}()

	var result struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if len(result.Result) == 0 {
		log.Printf("[Cloudflare] IP %s not found in firewall rules", ip)

		return nil // IP not blocked
	}

	log.Printf("[Cloudflare] Found rule %s for IP %s, deleting", result.Result[0].ID, ip)

	// Delete the rule
	req, err = http.NewRequestWithContext(ctx,
		http.MethodDelete,
		fmt.Sprintf("%s/zones/%s/firewall/access_rules/rules/%s",
			c.baseURL, c.zoneID, result.Result[0].ID),
		nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)

	resp, err = c.doWithRetry(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close response body: %v", err)
		}
	}()

	return c.checkResponse(resp)
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
			log.Printf("[Cloudflare] Could not determine ban duration for IP %s, skipping", rule.Configuration.Value)

			continue
		}

		// Store in the sync.Map for cleanup
		banUntil := rule.CreatedOn.Add(banDuration)
		c.blockedIPs.Store(rule.Configuration.Value, banUntil)

		blocks = append(blocks, persistence.BlockedIP{
			IP:       rule.Configuration.Value,
			BannedAt: rule.CreatedOn,
			BanUntil: banUntil,
		})
	}

	log.Printf("[Cloudflare] Loaded %d existing blocks", len(blocks))

	return blocks, nil
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
