// Package fail2ban contains the Fail2ban mechanism for the plugin.
package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	lAllow "github.com/tomMoulard/fail2ban/pkg/list/allow"
	lDeny "github.com/tomMoulard/fail2ban/pkg/list/deny"
	logger "github.com/tomMoulard/fail2ban/pkg/log"
	uAllow "github.com/tomMoulard/fail2ban/pkg/url/allow"
	uDeny "github.com/tomMoulard/fail2ban/pkg/url/deny"
)

func init() {
	log.SetOutput(os.Stdout)
}

// Urlregexp struct.
type Urlregexp struct {
	Regexp string `yaml:"regexp"`
	Mode   string `yaml:"mode"`
}

// LoggerDEBUG debug logger. noop by default.
var LoggerDEBUG = logger.New(os.Stdout, "DEBUG: Fail2Ban: ", log.Ldate|log.Ltime|log.Lshortfile)

// Rules struct fail2ban config.
type Rules struct {
	Bantime    string      `yaml:"bantime"`  // exprimate in a smart way: 3m
	Enabled    bool        `yaml:"enabled"`  // enable or disable the jail
	Findtime   string      `yaml:"findtime"` // exprimate in a smart way: 3m
	Maxretry   int         `yaml:"maxretry"`
	Urlregexps []Urlregexp `yaml:"urlregexps"`
}

// List struct.
type List struct {
	IP    []string
	Files []string
}

// Config struct.
type Config struct {
	Denylist  List  `yaml:"denylist"`
	Allowlist List  `yaml:"allowlist"`
	Rules     Rules `yaml:"port"`

	// deprecated
	Blacklist List `yaml:"blacklist"`
	// deprecated
	Whitelist List `yaml:"whitelist"`
}

// CreateConfig populates the Config data object.
func CreateConfig() *Config {
	return &Config{
		Rules: Rules{
			Bantime:  "300s",
			Findtime: "120s",
			Enabled:  true,
		},
	}
}

// RulesTransformed transformed Rules struct.
type RulesTransformed struct {
	Bantime        time.Duration
	Findtime       time.Duration
	URLRegexpAllow []*regexp.Regexp
	URLRegexpBan   []*regexp.Regexp
	MaxRetry       int
	Enabled        bool
}

// TransformRule morph a Rules object into a RulesTransformed.
func TransformRule(r Rules) (RulesTransformed, error) {
	bantime, err := time.ParseDuration(r.Bantime)
	if err != nil {
		return RulesTransformed{}, fmt.Errorf("failed to parse bantime duration: %w", err)
	}

	log.Printf("Bantime: %s", bantime)

	findtime, err := time.ParseDuration(r.Findtime)
	if err != nil {
		return RulesTransformed{}, fmt.Errorf("failed to parse findtime duration: %w", err)
	}

	log.Printf("Findtime: %s", findtime)

	var regexpAllow []*regexp.Regexp

	var regexpBan []*regexp.Regexp

	for _, rg := range r.Urlregexps {
		log.Printf("using mode %q for rule %q", rg.Mode, rg.Regexp)

		re, err := regexp.Compile(rg.Regexp)
		if err != nil {
			return RulesTransformed{}, fmt.Errorf("failed to compile regexp %q: %w", rg.Regexp, err)
		}

		switch rg.Mode {
		case "allow":
			regexpAllow = append(regexpAllow, re)
		case "block":
			regexpBan = append(regexpBan, re)
		default:
			log.Printf("mode %q is not known, the rule %q cannot not be applied", rg.Mode, rg.Regexp)
		}
	}

	rules := RulesTransformed{
		Bantime:        bantime,
		Findtime:       findtime,
		URLRegexpAllow: regexpAllow,
		URLRegexpBan:   regexpBan,
		MaxRetry:       r.Maxretry,
		Enabled:        r.Enabled,
	}

	log.Printf("FailToBan Rules : '%+v'", rules)

	return rules, nil
}

// Fail2Ban holds the necessary components of a Traefik plugin.
type Fail2Ban struct {
	next  http.Handler
	name  string
	rules RulesTransformed

	muIP     sync.Mutex
	ipViewed map[string]ipchecking.IPViewed
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

	rules, err := TransformRule(config.Rules)
	if err != nil {
		return nil, fmt.Errorf("error when Transforming rules: %w", err)
	}

	urlAllow := uAllow.New(rules.URLRegexpAllow)

	log.Println("Plugin: FailToBan is up and running")

	f2b := &Fail2Ban{
		next:     next,
		name:     name,
		rules:    rules,
		ipViewed: make(map[string]ipchecking.IPViewed),
	}

	urlDeny := uDeny.New(rules.URLRegexpBan, &f2b.muIP, &f2b.ipViewed)

	return chain.New(
		next,
		denyHandler,
		allowHandler,
		urlDeny,
		urlAllow,
		f2b,
	), nil
}

// ServeHTTP iterates over every headers to match the ones specified in the
// configuration and return nothing if regexp failed.
func (u *Fail2Ban) ServeHTTP(rw http.ResponseWriter, req *http.Request) (*chain.Status, error) {
	data := data.GetData(req)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	if !u.shouldAllow(data.RemoteIP) {
		return &chain.Status{Return: true}, nil
	}

	return nil, nil
}

// shouldAllow check if the request should be allowed.
func (u *Fail2Ban) shouldAllow(remoteIP string) bool {
	u.muIP.Lock()
	defer u.muIP.Unlock()

	ip, foundIP := u.ipViewed[remoteIP]

	// Fail2Ban
	if !foundIP {
		u.ipViewed[remoteIP] = ipchecking.IPViewed{
			Viewed: time.Now(),
			Count:  1,
		}

		LoggerDEBUG.Printf("welcome %q", remoteIP)

		return true
	}

	if ip.Denied {
		if time.Now().Before(ip.Viewed.Add(u.rules.Bantime)) {
			u.ipViewed[remoteIP] = ipchecking.IPViewed{
				Viewed: ip.Viewed,
				Count:  ip.Count + 1,
				Denied: true,
			}

			LoggerDEBUG.Printf("%q is still banned since %q, %d request",
				remoteIP, ip.Viewed.Format(time.RFC3339), ip.Count+1)

			return false
		}

		u.ipViewed[remoteIP] = ipchecking.IPViewed{
			Viewed: time.Now(),
			Count:  1,
			Denied: false,
		}

		LoggerDEBUG.Println(remoteIP + " is no longer banned")

		return true
	}

	if time.Now().Before(ip.Viewed.Add(u.rules.Findtime)) {
		if ip.Count+1 >= u.rules.MaxRetry {
			u.ipViewed[remoteIP] = ipchecking.IPViewed{
				Viewed: time.Now(),
				Count:  ip.Count + 1,
				Denied: true,
			}

			LoggerDEBUG.Println(remoteIP + " is now banned temporarily")

			return false
		}

		u.ipViewed[remoteIP] = ipchecking.IPViewed{
			Viewed: ip.Viewed,
			Count:  ip.Count + 1,
			Denied: false,
		}

		LoggerDEBUG.Printf("welcome back %q for the %d time", remoteIP, ip.Count+1)

		return true
	}

	u.ipViewed[remoteIP] = ipchecking.IPViewed{
		Viewed: time.Now(),
		Count:  1,
		Denied: false,
	}

	LoggerDEBUG.Printf("welcome back %q", remoteIP)

	return true
}
