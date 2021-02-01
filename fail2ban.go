package fail2ban

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tommoulard/fail2ban/files"
	"github.com/tommoulard/fail2ban/ipchecking"
)

// IPViewed struct
type IPViewed struct {
	viewed      time.Time
	nb          int
	blacklisted bool
}

// Logger Main logger
var (
	Logger       = log.New(os.Stdout, "Fail2Ban: ", log.Ldate|log.Ltime|log.Lshortfile)
	LoggerConfig = log.New(os.Stdout, "Fail2Ban_config: ", log.Ldate|log.Ltime|log.Lshortfile)
	ipViewed     = map[string]IPViewed{}
)

// Rules struct fail2ban config
type Rules struct {
	// Ignorecommand     string        `yaml:"igonecommand"`
	Bantime   string   `yaml:"bantime"`  //exprimate in a smart way: 3m
	Findtime  string   `yaml:"findtime"` //exprimate in a smart way: 3m
	Maxretry  int      `yaml:"maxretry"`
	Urlregexp []string `yaml:"urlregexp"`
	// Backend           string        `yaml:"backend"`     //maybe we have to change this to another things or just delete it if its useless
	// Usedns            string        `yaml:"usedns"`      //maybe change string by a int for limit the size (yes:0, warn:1, no:2, raw:3)
	// Logencoding       string        `yaml:"logencoding"` //maybe useless for our project (utf-8, ascii)
	Enabled bool `yaml:"enabled"` //enable or disable the jail
	// Mode              string        `yaml:"mode"`        //same than usedns
	// Filter            string        `yaml:"filter"`      //= %(name)s[mode=%(mode)s] maybe change for a []string
	// Destemail         string        `yaml:"destemail"`
	// Sender            string        `yaml:"sender"`
	// Mta               string        `yaml:"mta"`      //same than usedns
	// Protocol          string        `yaml:"protocol"` //maybe int (tcp:0, udp:1)
	// Chain             string        `yaml:"chain"`    //maybe useless because handle by traefik chain
	Ports string `yaml:"ports"`
	// Fail2banAgent     string        `yaml:"fail2ban_agent"`
	// Banaction         string        `yaml:"banaction"`          //maybe useless because we are the firewall ?
	// BanactionAllports string        `yaml:"banaction_allports"` //same as above
	// ActionAbuseipdb   string        `yaml:"action_abuseipdb"`
	// Action            string        `yaml:"action"` //maybe change for []string
}

// List struct
type List struct {
	IP    []string
	Files []string
}

// Config struct
type Config struct {
	Blacklist List  `yaml:"blacklist"`
	Whitelist List  `yaml:"whitelist"`
	Rules     Rules `yaml:"port"`
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
	bantime   time.Duration
	findtime  time.Duration
	urlregexp []string
	maxretry  int
	enabled   bool
	ports     [2]int
}

// TransformRule morph a Rules object into a RulesTransformed
func TransformRule(r Rules) (RulesTransformed, error) {
	bantime, err := time.ParseDuration(r.Bantime)
	if err != nil {
		return RulesTransformed{}, err
	}
	LoggerConfig.Printf("Bantime: %s", bantime)

	findtime, err := time.ParseDuration(r.Findtime)
	if err != nil {
		return RulesTransformed{}, err
	}
	LoggerConfig.Printf("Findtime: %s", findtime)

	ports := strings.Split(r.Ports, ":")
	if len(ports) != 2 {
		return RulesTransformed{},
			fmt.Errorf(`Could not parse Ports, bad format (hint: use something like "80:443" to filter all ports from 80 to 443)`)
	}

	portStart, err := strconv.Atoi(ports[0])
	if err != nil {
		return RulesTransformed{}, err
	}

	portEnd, err := strconv.Atoi(ports[1])
	if err != nil {
		return RulesTransformed{}, err
	}
	LoggerConfig.Printf("Ports range from %d to %d", portStart, portEnd)

	rules := RulesTransformed{
		bantime:   bantime,
		findtime:  findtime,
		urlregexp: r.Urlregexp,
		maxretry:  r.Maxretry,
		enabled:   r.Enabled,
		ports:     [2]int{portStart, portEnd},
	}
	LoggerConfig.Printf("FailToBan Rules : '%+v'", rules)
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
	whiteips, err := ImportIP(config.Whitelist)
	if err != nil {
		return nil, err
	}

	whitelist, err := ipchecking.StrToIP(whiteips)
	if err != nil {
		return nil, err
	}

	for _, whiteip := range whitelist {
		LoggerConfig.Printf("Whitelisted: '%s'", whiteip.ToString())
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
		LoggerConfig.Printf("Blacklisted: '%s'", blackip.ToString())
	}

	rules, err := TransformRule(config.Rules)
	if err != nil {
		return nil, fmt.Errorf("Error when Transforming rules: %+v", err)
	}

	Logger.Println("Plugin: FailToBan is up and running")
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
	if !u.rules.enabled {
		u.next.ServeHTTP(rw, req)
		return
	}

	remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		Logger.Println(remoteIP + " is not a valid IP or a IP/NET")
		return
	}

	// Blacklist
	for _, ip := range u.blacklist {
		if ip.CheckIPInSubnet(remoteIP) {
			Logger.Println(remoteIP + " is in blacklisted")
			rw.WriteHeader(http.StatusForbidden)
			return
		}
	}

	// Whitelist
	for _, ip := range u.whitelist {
		if ip.CheckIPInSubnet(remoteIP) {
			u.next.ServeHTTP(rw, req)
			return
		}
	}

	ip := ipViewed[remoteIP]

	for _, reg := range u.rules.urlregexp {
		url := req.Host + req.URL.String()
		if matched, err := regexp.Match(reg, []byte(url)); err != nil || matched {
			Logger.Printf("Url ('%s') was matched by regexp: '%s'", url, reg)
			rw.WriteHeader(http.StatusForbidden)
			ipViewed[remoteIP] = IPViewed{time.Now(), ip.nb + 1, true}
			return
		}
	}

	//Fail2Ban
	if reflect.DeepEqual(ip, IPViewed{}) {
		ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}
	} else {
		if ip.blacklisted {
			if time.Now().Before(ip.viewed.Add(u.rules.bantime)) {
				ipViewed[remoteIP] = IPViewed{ip.viewed, ip.nb + 1, true}
				Logger.Println(remoteIP + " is in blacklist mode")
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}
			Logger.Println(remoteIP + " is now back in whitelist mode")
		} else if time.Now().Before(ip.viewed.Add(u.rules.findtime)) {
			if ip.nb+1 >= u.rules.maxretry {
				ipViewed[remoteIP] = IPViewed{time.Now(), ip.nb + 1, true}
				Logger.Println(remoteIP + " is in blacklist mode")
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			ipViewed[remoteIP] = IPViewed{ip.viewed, ip.nb + 1, false}
		} else {
			ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}
		}
	}
	u.next.ServeHTTP(rw, req)
}
