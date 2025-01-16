// Package fail2ban contains the Fail2ban mechanism for the plugin.
package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/cloudflare"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
	"github.com/tomMoulard/fail2ban/pkg/persistence"
	"github.com/tomMoulard/fail2ban/pkg/rules"
)

func init() {
	log.SetOutput(os.Stdout)
}

// List struct.
type List struct {
	IP    []string `json:"ip"    label:"IP addresses"                  toml:"ip"    yaml:"ip"`
	Files []string `json:"files" label:"Files containing IP addresses" toml:"files" yaml:"files"`
}

// CloudflareConfig holds the Cloudflare-specific configuration.
type CloudflareConfig struct {
	Enabled    bool   `json:"enabled"    label:"Enable Cloudflare integration" toml:"enabled"    yaml:"enabled"`
	APIToken   string `json:"apiToken"   label:"Cloudflare API Token"          toml:"apiToken"   yaml:"apiToken"`
	ZoneID     string `json:"zoneId"     label:"Cloudflare Zone ID"            toml:"zoneId"     yaml:"zoneId"`
	IPHeader   string `json:"ipHeader"   label:"Header for real IP"            toml:"ipHeader"   yaml:"ipHeader"`
	MaxRetries int    `json:"maxRetries" label:"Max API retries"               toml:"maxRetries" yaml:"maxRetries"`
	RetryDelay int    `json:"retryDelay" label:"Retry delay (seconds)"         toml:"retryDelay" yaml:"retryDelay"`
}

// Config struct.
type Config struct {
	Denylist        List             `json:"denylist"        toml:"denylist"        yaml:"denylist"`
	Allowlist       List             `json:"allowlist"       toml:"allowlist"       yaml:"allowlist"`
	Rules           rules.Rules      `json:"rules"           toml:"rules"           yaml:"rules"`
	IPHeader        string           `json:"ipHeader"        toml:"ipHeader"        yaml:"ipHeader"`
	Cloudflare      CloudflareConfig `json:"cloudflare"      toml:"cloudflare"      yaml:"cloudflare"`
	PersistencePath string           `json:"persistencePath" toml:"persistencePath" yaml:"persistencePath"`
}

const (
	DefaultMaxRetries = 3
	DefaultRetryDelay = 1
)

// CreateConfig populates the Config data object.
func CreateConfig() *Config {
	return &Config{
		Rules: rules.Rules{
			Bantime:  "300s",
			Findtime: "120s",
			Enabled:  true,
		},
		IPHeader: "CF-Connecting-IP",
		Cloudflare: CloudflareConfig{
			Enabled:    false,
			MaxRetries: DefaultMaxRetries,
			RetryDelay: DefaultRetryDelay,
		},
	}
}

// ImportIP extract all ip from config sources.
func ImportIP(list List) ([]string, error) {
	var rlist []string

	for _, ip := range list.Files {
		content, err := os.ReadFile(ip)
		if err != nil {
			return nil, fmt.Errorf("error when getting file content: %w", err)
		}

		rlist = append(rlist, strings.Split(string(content), "\n")...)
		if len(rlist) > 1 {
			rlist = rlist[:len(rlist)-1]
		}
	}

	rlist = append(rlist, list.IP...)

	return rlist, nil
}

func setupPersistence(ctx context.Context, path string) (persistence.Store, []persistence.BlockedIP, error) {
	if path == "" {
		return nil, nil, nil
	}

	store := persistence.NewFileStore(path)

	blocks, err := store.Load(ctx)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("failed to load blocked IPs from persistence: %w", err)
		}
		// If file doesn't exist, return empty store
		return store, nil, nil
	}

	fmt.Printf("Loaded %d blocked IPs from persistence", len(blocks))

	return store, blocks, nil
}

func setupCloudflare(ctx context.Context, config *Config) (*cloudflare.Client, []persistence.BlockedIP, error) {
	if !config.Cloudflare.Enabled {
		fmt.Println("[Cloudflare] Integration disabled")

		return nil, nil, nil
	}

	if config.Cloudflare.APIToken == "" {
		return nil, nil, errors.New("cloudflare API token is required when Cloudflare integration is enabled")
	}

	if config.Cloudflare.ZoneID == "" {
		return nil, nil, errors.New("cloudflare Zone ID is required when Cloudflare integration is enabled")
	}

	fmt.Printf("[Cloudflare] Setting up client with token=%s..., zoneID=%s\n",
		config.Cloudflare.APIToken[:4], config.Cloudflare.ZoneID)

	fmt.Println("[Cloudflare] Integration enabled and configured")

	maxRetries := config.Cloudflare.MaxRetries
	if maxRetries == 0 {
		maxRetries = DefaultMaxRetries
	}

	retryDelay := time.Duration(config.Cloudflare.RetryDelay) * time.Second
	if retryDelay == 0 {
		retryDelay = DefaultRetryDelay * time.Second
	}

	transformedRules, err := rules.TransformRule(config.Rules)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to transform rules: %w", err)
	}

	cf := cloudflare.NewClient(ctx, config.Cloudflare.APIToken, config.Cloudflare.ZoneID,
		maxRetries, retryDelay, transformedRules)

	// Test the client by loading existing blocks
	blocks, err := cf.LoadExistingBlocks(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to test Cloudflare client: %w", err)
	}

	return cf, blocks, nil
}

// Add this function to validate the persistence path.
func validatePersistencePath(path string) error {
	if path == "" {
		return nil
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid persistence path: %w", err)
	}

	// Check if directory exists or can be created
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, persistence.DirectoryPermission); err != nil {
		return fmt.Errorf("failed to create persistence directory: %w", err)
	}

	// Try to create a test file
	testFile := filepath.Join(dir, ".test")
	if err := os.WriteFile(testFile, []byte("test"), persistence.FilePermission); err != nil {
		return fmt.Errorf("persistence directory is not writable: %w", err)
	}
	os.Remove(testFile)

	return nil
}

// New creates a new fail2ban plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if !config.Rules.Enabled {
		fmt.Println("Plugin: FailToBan is disabled")

		return next, nil
	}

	fmt.Printf("[Fail2Ban] Persistence path configured as: %s\n", config.PersistencePath)

	// Validate persistence path
	if err := validatePersistencePath(config.PersistencePath); err != nil {
		return nil, fmt.Errorf("persistence validation failed: %w", err)
	}

	// Configure persistence
	var store persistence.Store

	if config.PersistencePath != "" {
		absPath, _ := filepath.Abs(config.PersistencePath) // Error already checked in validation
		store = persistence.NewFileStore(absPath)
		fmt.Printf("[Fail2Ban] Configured persistence at: %s\n", absPath)
	}

	// Configure data package with IP header
	data.SetConfig(data.Config{
		IPHeader: config.IPHeader,
	})

	if config.Cloudflare.Enabled && config.IPHeader == "" {
		// Use Cloudflare's header as fallback if no custom header is set
		data.SetConfig(data.Config{
			IPHeader: "CF-Connecting-IP",
		})
	}

	transformedRules, err := rules.TransformRule(config.Rules)
	if err != nil {
		return nil, fmt.Errorf("failed to transform rules: %w", err)
	}

	var cf *cloudflare.Client

	var cfBlocks []persistence.BlockedIP

	var cfErr error

	if config.Cloudflare.Enabled {
		cf, cfBlocks, cfErr = setupCloudflare(ctx, config)

		if cfErr != nil {
			return nil, fmt.Errorf("failed to setup Cloudflare: %w", cfErr)
		}

		fmt.Printf("[Cloudflare] Successfully initialized client and loaded %d existing blocks\n", len(cfBlocks))
	}

	f2b := fail2ban.New(ctx, transformedRules, cf, store)

	// Restore Cloudflare blocks
	for _, block := range cfBlocks {
		f2b.RestoreBlock(ctx, block.IP, block.BannedAt, block.BanUntil, block.RuleID)
	}

	return &Fail2Ban{
		next:   next,
		name:   name,
		config: config,
		f2b:    f2b,
		cf:     cf,
	}, nil
}

// Fail2Ban struct.
type Fail2Ban struct {
	next   http.Handler
	name   string
	config *Config
	f2b    *fail2ban.Fail2Ban
	cf     *cloudflare.Client
}

func (f *Fail2Ban) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// Use data package to get the real IP
	req, err := data.ServeHTTP(rw, req.WithContext(ctx))
	if err != nil {
		fmt.Printf("Failed to process request data: %v\n", err)
		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	d := data.GetData(req)
	if d == nil {
		fmt.Println("No request data available")
		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	remoteIP := d.RemoteIP

	if !f.f2b.ShouldAllow(ctx, remoteIP) {
		rw.WriteHeader(http.StatusForbidden)

		return
	}

	f.next.ServeHTTP(rw, req)
}
