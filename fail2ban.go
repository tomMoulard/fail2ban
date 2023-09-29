package fail2ban

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tomMoulard/fail2ban/files"
	"github.com/tomMoulard/fail2ban/ipchecking"
)

// IPViewed struct
type IPViewed struct {
	viewed      time.Time
	nb          int
	blacklisted bool
}

// Urlregexp struct
type Urlregexp struct {
	Regexp string `yaml:"regexp"`
	Mode   string `yaml:"mode"`
}

var (
	// LoggerINFO Main logger
	LoggerINFO = log.New(io.Discard, "INFO: Fail2Ban: ", log.Ldate|log.Ltime|log.Lshortfile)
	// LoggerDEBUG debug logger
	LoggerDEBUG = log.New(io.Discard, "DEBUG: Fail2Ban: ", log.Ldate|log.Ltime|log.Lshortfile)

	muIP     sync.Mutex
	ipViewed = map[string]IPViewed{}
)

// Rules struct fail2ban config
type Rules struct {
	Bantime    string      `yaml:"bantime"`  // exprimate in a smart way: 3m
	Enabled    bool        `yaml:"enabled"`  // enable or disable the jail
	Findtime   string      `yaml:"findtime"` // exprimate in a smart way: 3m
	Maxretry   int         `yaml:"maxretry"`
	Urlregexps []Urlregexp `yaml:"urlregexps"`
}

// List struct
type List struct {
	IP    []string
	Files []string
}

// Config struct
type Config struct {
	Blacklist List   `yaml:"blacklist"`
	Whitelist List   `yaml:"whitelist"`
	Rules     Rules  `yaml:"port"`
	LogLevel  string `yaml:"loglevel"`
}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{
		Rules: Rules{
			Bantime:  "300s",
			Findtime: "120s",
			Enabled:  true,
		},
	}
}

// RulesTransformed transformed Rules struct
type RulesTransformed struct {
	bantime        time.Duration
	findtime       time.Duration
	urlregexpAllow []string
	urlregexpBan   []string
	maxretry       int
	enabled        bool
}

// TransformRule morph a Rules object into a RulesTransformed
func TransformRule(r Rules) (RulesTransformed, error) {
	bantime, err := time.ParseDuration(r.Bantime)
	if err != nil {
		return RulesTransformed{}, err
	}
	LoggerINFO.Printf("Bantime: %s", bantime)

	findtime, err := time.ParseDuration(r.Findtime)
	if err != nil {
		return RulesTransformed{}, err
	}
	LoggerINFO.Printf("Findtime: %s", findtime)

	var regexpAllow []string
	var regexpBan []string

	for _, rg := range r.Urlregexps {
		LoggerINFO.Printf("using mode %s for rule %q", rg.Mode, rg.Regexp)
		switch rg.Mode {
		case "allow":
			regexpAllow = append(regexpAllow, rg.Regexp)
		case "block":
			regexpBan = append(regexpBan, rg.Regexp)
		default:
			LoggerINFO.Printf("mode %s is not known, the rule %s cannot not be applied", rg.Mode, rg.Regexp)
		}
	}

	rules := RulesTransformed{
		bantime:        bantime,
		findtime:       findtime,
		urlregexpAllow: regexpAllow,
		urlregexpBan:   regexpBan,
		maxretry:       r.Maxretry,
		enabled:        r.Enabled,
	}
	LoggerINFO.Printf("FailToBan Rules : '%+v'", rules)
	return rules, nil
}

// Fail2Ban holds the necessary components of a Traefik plugin
type Fail2Ban struct {
	next      http.Handler
	name      string
	whitelist []ipchecking.IP
	blacklist []ipchecking.IP
	rules     RulesTransformed
}

// ImportIP extract all ip from config sources
func ImportIP(list List) ([]string, error) {
	var rlist []string
	for _, ip := range list.Files {
		content, err := files.GetFileContent(ip)
		if err != nil {
			return nil, err
		}
		rlist = append(rlist, strings.Split(content, "\n")...)
		if len(rlist) > 1 {
			rlist = rlist[:len(rlist)-1]
		}
	}
	rlist = append(rlist, list.IP...)

	return rlist, nil
}

// New instantiates and returns the required components used to handle a HTTP request
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	switch config.LogLevel {
	case "INFO":
		LoggerINFO.SetOutput(os.Stdout)
	case "DEBUG":
		LoggerINFO.SetOutput(os.Stdout)
		LoggerDEBUG.SetOutput(os.Stdout)
	}

	whiteips, err := ImportIP(config.Whitelist)
	if err != nil {
		return nil, err
	}

	whitelist, err := ipchecking.StrToIP(whiteips)
	if err != nil {
		return nil, err
	}

	for _, whiteip := range whitelist {
		LoggerINFO.Printf("Whitelisted: '%s'", whiteip.ToString())
	}

	blackips, err := ImportIP(config.Blacklist)
	if err != nil {
		return nil, err
	}

	blacklist, err := ipchecking.StrToIP(blackips) // Do not mistake with Black Eyed Peas
	if err != nil {
		return nil, err
	}

	for _, blackip := range blacklist {
		LoggerINFO.Printf("Blacklisted: '%s'", blackip.ToString())
	}

	rules, err := TransformRule(config.Rules)
	if err != nil {
		return nil, fmt.Errorf("error when Transforming rules: %+v", err)
	}

	LoggerINFO.Println("Plugin: FailToBan is up and running")
	return &Fail2Ban{
		next:      next,
		name:      name,
		whitelist: whitelist,
		blacklist: blacklist,
		rules:     rules,
	}, nil
}

// Iterate over every headers to match the ones specified in the config and
// return nothing if regexp failed.
func (u *Fail2Ban) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	LoggerDEBUG.Printf("New request: %v", req)

	if !u.rules.enabled {
		u.next.ServeHTTP(rw, req)
		return
	}

	remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		LoggerDEBUG.Println(remoteIP + " is not a valid IP or a IP/NET")
		return
	}

	// Blacklist
	for _, ip := range u.blacklist {
		if ip.CheckIPInSubnet(remoteIP) {
			LoggerDEBUG.Println(remoteIP + " is blacklisted")
			rw.WriteHeader(http.StatusForbidden)
			return
		}
	}

	// Whitelist
	for _, ip := range u.whitelist {
		if ip.CheckIPInSubnet(remoteIP) {
			LoggerDEBUG.Println(remoteIP + " is whitelisted")
			u.next.ServeHTTP(rw, req)
			return
		}
	}

	// Urlregexp ban
	muIP.Lock()
	defer muIP.Unlock()
	ip := ipViewed[remoteIP]
	url := req.URL.String()
	urlBytes := []byte(url)

	for _, reg := range u.rules.urlregexpBan {
		if matched, err := regexp.Match(reg, urlBytes); err != nil || matched {
			LoggerDEBUG.Printf("Url ('%s') was matched by regexpBan: '%s' for '%s'", url, reg, req.Host)
			rw.WriteHeader(http.StatusForbidden)
			ipViewed[remoteIP] = IPViewed{time.Now(), ip.nb + 1, true}
			return
		}
	}

	// Urlregexp allow
	for _, reg := range u.rules.urlregexpAllow {
		if matched, err := regexp.Match(reg, urlBytes); err != nil || matched {
			LoggerDEBUG.Printf("Url ('%s') was matched by regexpAllow: '%s' for '%s'", url, reg, req.Host)
			u.next.ServeHTTP(rw, req)
			return
		}
	}

	// Fail2Ban
	if reflect.DeepEqual(ip, IPViewed{}) {
		LoggerDEBUG.Printf("welcome %s", remoteIP)
		ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}
	} else {
		if ip.blacklisted {
			if time.Now().Before(ip.viewed.Add(u.rules.bantime)) {
				ipViewed[remoteIP] = IPViewed{ip.viewed, ip.nb + 1, true}
				LoggerDEBUG.Printf("%s is still banned since %s, %d request",
					remoteIP, ip.viewed.Format(time.RFC3339), ip.nb+1)
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}
			LoggerDEBUG.Println(remoteIP + " is no longer banned")
		} else if time.Now().Before(ip.viewed.Add(u.rules.findtime)) {
			if ip.nb+1 >= u.rules.maxretry {
				ipViewed[remoteIP] = IPViewed{time.Now(), ip.nb + 1, true}
				LoggerDEBUG.Println(remoteIP + " is now banned temporarily")
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			ipViewed[remoteIP] = IPViewed{ip.viewed, ip.nb + 1, false}
			LoggerDEBUG.Printf("welcome back %s for the %d time", remoteIP, ip.nb+1)
		} else {
			ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}
			LoggerDEBUG.Printf("welcome back %s", remoteIP)
		}
	}
	u.next.ServeHTTP(rw, req)
}
