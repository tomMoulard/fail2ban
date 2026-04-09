// Package fail2ban contains the Fail2ban mechanism for the plugin.
package fail2ban

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
	f2bHandler "github.com/tomMoulard/fail2ban/pkg/fail2ban/handler"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	lAllow "github.com/tomMoulard/fail2ban/pkg/list/allow"
	lDeny "github.com/tomMoulard/fail2ban/pkg/list/deny"
	"github.com/tomMoulard/fail2ban/pkg/response/status"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	uAllow "github.com/tomMoulard/fail2ban/pkg/url/allow"
	uDeny "github.com/tomMoulard/fail2ban/pkg/url/deny"
)

func init() {
	log.SetOutput(os.Stdout)
}

var (
	globalJails = make(map[string]*fail2ban.Fail2Ban)
	globalMu    sync.Mutex
)

func getOrCreateSharedJail(name string, config *Config, rules rules.RulesTransformed, allowNetIPs ipchecking.NetIPs) *fail2ban.Fail2Ban {
	jailKey := fmt.Sprintf("%s-%x", name, sha256.Sum256([]byte(fmt.Sprintf("%v", config))))

	globalMu.Lock()
	defer globalMu.Unlock()

	if f2b, exists := globalJails[jailKey]; exists {
		log.Printf("Plugin: FailToBan using existing shared jail for middleware %s", jailKey)

		return f2b
	}
	// Keep at most one shared jail per middleware name.
	// Old handlers keep their pointer; this only bounds registry growth.
	prefix := name + "-"
	for key := range globalJails {
		if strings.HasPrefix(key, prefix) && key != jailKey {
			delete(globalJails, key)
		}
	}

	f2b := fail2ban.New(rules, allowNetIPs)
	globalJails[jailKey] = f2b

	log.Printf("Plugin: FailToBan created new shared jail for middleware %s", jailKey)

	return f2b
}

// List struct.
type List struct {
	IP    []string
	Files []string
}

// Config struct.
type Config struct {
	Denylist   List        `yaml:"denylist"`
	Allowlist  List        `yaml:"allowlist"`
	Rules      rules.Rules `yaml:"port"`
	SharedJail bool        `yaml:"sharedJail"`

	// deprecated
	Blacklist List `yaml:"blacklist"`
	// deprecated
	Whitelist List `yaml:"whitelist"`
}

// CreateConfig populates the Config data object.
func CreateConfig() *Config {
	return &Config{
		Rules: rules.Rules{
			Bantime:  "300s",
			Findtime: "120s",
			Enabled:  true,
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

// New instantiates and returns the required components used to handle a HTTP
// request.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if !config.Rules.Enabled {
		log.Println("Plugin: FailToBan is disabled")

		return next, nil
	}

	allowIPs, err := ImportIP(config.Allowlist)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowlist IPs: %w", err)
	}

	if len(config.Whitelist.IP) > 0 || len(config.Whitelist.Files) > 0 {
		log.Println("Plugin: FailToBan: 'whitelist' is deprecated, please use 'denylist' instead")

		whiteips, err := ImportIP(config.Whitelist)
		if err != nil {
			return nil, fmt.Errorf("failed to parse whitelist IPs: %w", err)
		}

		allowIPs = append(allowIPs, whiteips...)
	}

	allowNetIPs, err := ipchecking.ParseNetIPs(allowIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowlist IPs: %w", err)
	}

	allowHandler, err := lAllow.New(allowIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse whitelist IPs: %w", err)
	}

	denyIPs, err := ImportIP(config.Denylist)
	if err != nil {
		return nil, fmt.Errorf("failed to parse denylist IPs: %w", err)
	}

	if len(config.Blacklist.IP) > 0 || len(config.Blacklist.Files) > 0 {
		log.Println("Plugin: FailToBan: 'blacklist' is deprecated, please use 'denylist' instead")

		blackips, err := ImportIP(config.Blacklist)
		if err != nil {
			return nil, fmt.Errorf("failed to parse blacklist IPs: %w", err)
		}

		denyIPs = append(denyIPs, blackips...)
	}

	denyHandler, err := lDeny.New(denyIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse blacklist IPs: %w", err)
	}

	rules, err := rules.TransformRule(config.Rules)
	if err != nil {
		return nil, fmt.Errorf("error when Transforming rules: %w", err)
	}

	// Get or create jail
	var f2b *fail2ban.Fail2Ban

	if config.SharedJail {
		f2b = getOrCreateSharedJail(name, config, rules, allowNetIPs)
	} else {
		// Create individual jail
		f2b = fail2ban.New(rules, allowNetIPs)

		log.Printf("Plugin: FailToBan created individual jail for middleware %s", name)
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

	return c, nil
}
