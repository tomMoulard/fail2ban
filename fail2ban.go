// Package fail2ban contains the Fail2ban mechanism for the plugin.
package fail2ban

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tomMoulard/fail2ban/files"
	"github.com/tomMoulard/fail2ban/ipchecking"
	logger "github.com/tomMoulard/fail2ban/log"
)

func init() {
	log.SetOutput(os.Stdout)
}

// IPViewed struct.
type IPViewed struct {
	viewed      time.Time
	nb          int
	blacklisted bool
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
	Blacklist List  `yaml:"blacklist"`
	Whitelist List  `yaml:"whitelist"`
	Rules     Rules `yaml:"port"`
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
	next      http.Handler
	name      string
	whitelist ipchecking.NetIPs
	blacklist ipchecking.NetIPs
	rules     RulesTransformed

	muIP     sync.Mutex
	ipViewed map[string]IPViewed
}

// ImportIP extract all ip from config sources.
func ImportIP(list List) ([]string, error) {
	var rlist []string

	for _, ip := range list.Files {
		content, err := files.GetFileContent(ip)
		if err != nil {
			return nil, fmt.Errorf("error when getting file content: %w", err)
		}

		rlist = append(rlist, strings.Split(content, "\n")...)
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

	whiteips, err := ImportIP(config.Whitelist)
	if err != nil {
		return nil, err
	}

	whitelist, err := ipchecking.ParseNetIPs(whiteips)
	if err != nil {
		return nil, fmt.Errorf("failed to parse whitelist IPs: %w", err)
	}

	blackips, err := ImportIP(config.Blacklist)
	if err != nil {
		return nil, err
	}

	blacklist, err := ipchecking.ParseNetIPs(blackips) // Do not mistake with Black Eyed Peas
	if err != nil {
		return nil, fmt.Errorf("failed to parse blacklist IPs: %w", err)
	}

	rules, err := TransformRule(config.Rules)
	if err != nil {
		return nil, fmt.Errorf("error when Transforming rules: %w", err)
	}

	log.Println("Plugin: FailToBan is up and running")

	return &Fail2Ban{
		next:      next,
		name:      name,
		whitelist: whitelist,
		blacklist: blacklist,
		rules:     rules,
		ipViewed:  make(map[string]IPViewed),
	}, nil
}

// ServeHTTP iterates over every headers to match the ones specified in the
// configuration and return nothing if regexp failed.
func (u *Fail2Ban) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	LoggerDEBUG.Printf("New request: %+v", *req)

	remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		LoggerDEBUG.Printf("failed to split remote address %q: %v", req.RemoteAddr, err)

		return
	}

	if !u.ShouldAllow(remoteIP, req.URL.String()) {
		rw.WriteHeader(http.StatusForbidden)

		return
	}

	u.next.ServeHTTP(rw, req)
}

// ShouldAllow check if the request should be allowed.
func (u *Fail2Ban) ShouldAllow(remoteIP, reqURL string) bool {
	// Blacklist
	if u.blacklist.Contains(remoteIP) {
		LoggerDEBUG.Println(remoteIP + " is blacklisted")

		return false
	}

	// Whitelist
	if u.whitelist.Contains(remoteIP) {
		LoggerDEBUG.Println(remoteIP + " is whitelisted")

		return true
	}

	// Urlregexp ban
	u.muIP.Lock()
	defer u.muIP.Unlock()

	ip, foundIP := u.ipViewed[remoteIP]
	urlBytes := []byte(reqURL)

	for _, reg := range u.rules.URLRegexpBan {
		if reg.Match(urlBytes) {
			u.ipViewed[remoteIP] = IPViewed{time.Now(), ip.nb + 1, true}

			LoggerDEBUG.Printf("Url (%q) was matched by regexpBan: %q for %q", reqURL, reg.String(), remoteIP)

			return false
		}
	}

	// Urlregexp allow
	for _, reg := range u.rules.URLRegexpAllow {
		if reg.Match(urlBytes) {
			LoggerDEBUG.Printf("Url (%q) was matched by regexpAllow: %q for %q", reqURL, reg.String(), remoteIP)

			return true
		}
	}

	// Fail2Ban
	if !foundIP {
		u.ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}

		LoggerDEBUG.Printf("welcome %q", remoteIP)

		return true
	}

	if ip.blacklisted {
		if time.Now().Before(ip.viewed.Add(u.rules.Bantime)) {
			u.ipViewed[remoteIP] = IPViewed{ip.viewed, ip.nb + 1, true}
			LoggerDEBUG.Printf("%q is still banned since %q, %d request",
				remoteIP, ip.viewed.Format(time.RFC3339), ip.nb+1)

			return false
		}

		u.ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}

		LoggerDEBUG.Println(remoteIP + " is no longer banned")

		return true
	}

	if time.Now().Before(ip.viewed.Add(u.rules.Findtime)) {
		if ip.nb+1 >= u.rules.MaxRetry {
			u.ipViewed[remoteIP] = IPViewed{time.Now(), ip.nb + 1, true}

			LoggerDEBUG.Println(remoteIP + " is now banned temporarily")

			return false
		}

		u.ipViewed[remoteIP] = IPViewed{ip.viewed, ip.nb + 1, false}
		LoggerDEBUG.Printf("welcome back %q for the %d time", remoteIP, ip.nb+1)

		return true
	}

	u.ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}

	LoggerDEBUG.Printf("welcome back %q", remoteIP)

	return true
}
