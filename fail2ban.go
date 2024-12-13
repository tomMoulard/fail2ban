// Package fail2ban contains the Fail2ban mechanism for the plugin.
package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/cloudflare"
	"github.com/tomMoulard/fail2ban/pkg/dashboard"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
	f2bHandler "github.com/tomMoulard/fail2ban/pkg/fail2ban/handler"
	lAllow "github.com/tomMoulard/fail2ban/pkg/list/allow"
	lDeny "github.com/tomMoulard/fail2ban/pkg/list/deny"
	"github.com/tomMoulard/fail2ban/pkg/persistence"
	"github.com/tomMoulard/fail2ban/pkg/provider"
	"github.com/tomMoulard/fail2ban/pkg/response/status"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	uAllow "github.com/tomMoulard/fail2ban/pkg/url/allow"
	uDeny "github.com/tomMoulard/fail2ban/pkg/url/deny"
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
	Denylist   List             `json:"denylist"   toml:"denylist"   yaml:"denylist"`
	Allowlist  List             `json:"allowlist"  toml:"allowlist"  yaml:"allowlist"`
	Rules      rules.Rules      `json:"rules"      toml:"rules"      yaml:"rules"`
	Cloudflare CloudflareConfig `json:"cloudflare" toml:"cloudflare" yaml:"cloudflare"`
	// Path to store blocked IPs (optional)
	PersistencePath string `json:"persistencePath" toml:"persistencePath" yaml:"persistencePath"`

	// deprecated
	Blacklist List `json:"blacklist" toml:"blacklist" yaml:"blacklist"`
	// deprecated
	Whitelist List `json:"whitelist" toml:"whitelist" yaml:"whitelist"`
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
		Cloudflare: CloudflareConfig{
			Enabled:    false,
			IPHeader:   "CF-Connecting-IP",
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

// Fail2Ban struct.
type Fail2Ban struct {
	next     http.Handler
	name     string
	config   *Config
	f2b      *fail2ban.Fail2Ban
	cf       *cloudflare.Client
	chain    http.Handler
	provider *provider.Provider
}

func setupPersistence(ctx context.Context, path string) ([]persistence.BlockedIP, error) {
	if path == "" {
		return nil, nil
	}

	store := persistence.NewFileStore(path)

	blocks, err := store.Load(ctx)
	if err != nil {
		log.Printf("Failed to load blocked IPs from persistence: %v", err)

		return nil, fmt.Errorf("failed to load blocked IPs from persistence: %w", err)
	}

	log.Printf("Loaded %d blocked IPs from persistence", len(blocks))

	return blocks, nil
}

func setupCloudflare(ctx context.Context, config *Config) (*cloudflare.Client, []persistence.BlockedIP, error) {
	if !config.Cloudflare.Enabled {
		return nil, nil, nil
	}

	if config.Cloudflare.APIToken == "" || config.Cloudflare.ZoneID == "" {
		return nil, nil, errors.New("cloudflare integration enabled but missing required configuration")
	}

	cf := cloudflare.NewClient(
		ctx,
		config.Cloudflare.APIToken,
		config.Cloudflare.ZoneID,
		config.Cloudflare.MaxRetries,
		time.Duration(config.Cloudflare.RetryDelay)*time.Second,
	)

	data.SetConfig(data.Config{
		IPHeader: config.Cloudflare.IPHeader,
	})

	// Load existing blocks from Cloudflare
	blocks, err := cf.LoadExistingBlocks(ctx)
	if err != nil {
		log.Printf("Failed to load blocks from Cloudflare: %v", err)

		return cf, nil, fmt.Errorf("failed to load blocks from Cloudflare: %w", err)
	}

	log.Printf("Loaded %d blocks from Cloudflare", len(blocks))

	return cf, blocks, nil
}

func setupIPLists(config *Config) ([]string, []string, error) {
	allowIPs, err := ImportIP(config.Allowlist)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse allowlist IPs: %w", err)
	}

	if len(config.Whitelist.IP) > 0 || len(config.Whitelist.Files) > 0 {
		log.Println("Plugin: FailToBan: 'whitelist' is deprecated, please use 'allowlist' instead")

		whiteips, err := ImportIP(config.Whitelist)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse whitelist IPs: %w", err)
		}

		allowIPs = append(allowIPs, whiteips...)
	}

	denyIPs, err := ImportIP(config.Denylist)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse denylist IPs: %w", err)
	}

	if len(config.Blacklist.IP) > 0 || len(config.Blacklist.Files) > 0 {
		log.Println("Plugin: FailToBan: 'blacklist' is deprecated, please use 'denylist' instead")

		blackips, err := ImportIP(config.Blacklist)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse blacklist IPs: %w", err)
		}

		denyIPs = append(denyIPs, blackips...)
	}

	return allowIPs, denyIPs, nil
}

// New instantiates and returns the required components used to handle a HTTP
// request.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if !config.Rules.Enabled {
		log.Println("Plugin: FailToBan is disabled")

		return next, nil
	}

	// Create provider config
	providerConfig := provider.CreateConfig()

	var blocks []persistence.BlockedIP

	persistedBlocks, err := setupPersistence(ctx, config.PersistencePath)
	if err == nil && persistedBlocks != nil {
		blocks = append(blocks, persistedBlocks...)
	}

	cf, cfBlocks, err := setupCloudflare(ctx, config)
	if err != nil {
		return nil, err
	}

	if cfBlocks != nil {
		blocks = append(blocks, cfBlocks...)
	}

	allowIPs, denyIPs, err := setupIPLists(config)
	if err != nil {
		return nil, err
	}

	allowHandler, err := lAllow.New(allowIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse whitelist IPs: %w", err)
	}

	denyHandler, err := lDeny.New(denyIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse blacklist IPs: %w", err)
	}

	rules, err := rules.TransformRule(config.Rules)
	if err != nil {
		return nil, fmt.Errorf("error when Transforming rules: %w", err)
	}

	log.Println("Plugin: FailToBan is up and running")

	f2b := fail2ban.New(rules, cf)

	// Restore blocked IPs
	for _, block := range blocks {
		if time.Now().Before(block.BanUntil) {
			f2b.RestoreBlock(block.IP, block.BannedAt, block.BanUntil)
		}
	}

	c := chain.New(
		next,
		denyHandler,
		allowHandler,
		uDeny.New(rules.URLRegexpBan, f2b),
		uAllow.New(rules.URLRegexpAllow),
		f2bHandler.New(f2b),
	)

	if rules.StatusCode != "" {
		statusCodeHandler, err := status.New(next, rules.StatusCode, f2b)
		if err != nil {
			return nil, fmt.Errorf("failed to create status handler: %w", err)
		}

		c.WithStatus(statusCodeHandler)
	}

	// Create dashboard handler
	dashboardHandler, err := dashboard.New(f2b, cf)
	if err != nil {
		return nil, fmt.Errorf("failed to create dashboard handler: %w", err)
	}

	// Create provider
	dashboardProvider, err := provider.New(ctx, providerConfig, dashboardHandler, name)
	if err != nil {
		return nil, fmt.Errorf("failed to create dashboard provider: %w", err)
	}

	if err := dashboardProvider.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize dashboard provider: %w", err)
	}

	return &Fail2Ban{
		next:     next,
		name:     name,
		config:   config,
		f2b:      f2b,
		cf:       cf,
		chain:    c,
		provider: dashboardProvider,
	}, nil
}

// Close implements the io.Closer interface.
func (f *Fail2Ban) Close() error {
	if f.provider != nil {
		if err := f.provider.Stop(); err != nil {
			log.Printf("Failed to stop dashboard provider: %v", err)
		}
	}

	if f.cf != nil {
		f.cf.Close()
	}

	return nil
}

// ServeHTTP implements the http.Handler interface.
func (f *Fail2Ban) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.chain.ServeHTTP(w, r)
}

func (f *Fail2Ban) GetDashboardHandler() (http.Handler, error) {
	handler, err := dashboard.New(f.f2b, f.cf)
	if err != nil {
		return nil, fmt.Errorf("failed to create dashboard handler: %w", err)
	}

	return handler, nil
}
