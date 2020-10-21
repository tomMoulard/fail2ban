package fail2ban

import (
	"context"
	"fmt"

	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/tommoulard/fail2ban/files"
	"github.com/tommoulard/fail2ban/ipChecking"
)

// IPViewed struct
type IPViewed struct {
	viewed      time.Time
	nb          int
	blacklisted bool
}

// Logger TestLogger
var (
	Logger   = log.New(os.Stdout, "Test", log.Ldate|log.Ltime|log.Lshortfile)
	ipViewed = map[string]IPViewed{}
)

// Rules struct fail2ban config
type rules struct {
	ignorecommand     string        `yaml:"igonecommand"`
	bantime           time.Duration `yaml:"bantime"`  //exprimate in second
	findtime          time.Duration `yaml:"findtime"` //exprimate in second
	maxretry          int           `yaml:"maxretry"`
	backend           string        `yaml:"backend"`     //maybe we have to change this to another things or just delete it if its useless
	usedns            string        `yaml:"usedns"`      //maybe change string by a int for limit the size (yes:0, warn:1, no:2, raw:3)
	logencoding       string        `yaml:"logencoding"` //maybe useless for our project (utf-8, ascii)
	enabled           bool          `yaml:"enabled"`     //enable or disable the jail
	mode              string        `yaml:"mode"`        //same than usedns
	filter            string        `yaml:"filter"`      //= %(name)s[mode=%(mode)s] maybe change for a []string
	destemail         string        `yaml:"destemail"`
	sender            string        `yaml:"sender"`
	mta               string        `yaml:"mta"`      //same than usedns
	protocol          string        `yaml:"protocol"` //maybe int (tcp:0, udp:1)
	chain             string        `yaml:"chain"`    //maybe useless because handle by traefik chain
	port              [2]int        `yaml:"port"`
	fail2banAgent     string        `yaml:"fail2ban_agent"`
	banaction         string        `yaml:"banaction"`          //maybe useless because we are the firewall ?
	banactionAllports string        `yaml:"banaction_allports"` //same as above
	actionAbuseipdb   string        `yaml:"action_abuseipdb"`
	action            string        `yaml:"action"` //maybe change for []string
}

// List struct
type List struct {
	Ip    []string
	Files []string
}

// Config struct
type Config struct {
	blacklist List
	whitelist List
	rules     rules
}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{
		Rules: Rule{
			bantime:  "300",
			findtime: "120",
			enabled:  true,
		},
	}
}

// Fail2Ban holds the necessary components of a Traefik plugin
type Fail2Ban struct {
	next      http.Handler
	name      string
	whitelist []ipChecking.Ip
	blacklist []ipChecking.Ip
	rules     rules
}

func ImportIP(list List) ([]string, error) {
	var rlist []string
	for _, ip := range list.Files {

		content, err := files.GetFileContent(ip)
		if err != nil {
			return nil, err
		}
		rlist = append(rlist, strings.Split(content, "\n")...)
	}
	if len(rlist) > 1 {
		rlist = rlist[:len(rlist)-1]
	}
	rlist = append(rlist, list.Ip...)

	return rlist, nil
}

// New instantiates and returns the required components used to handle a HTTP request
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.rules.bantime == "" || config.rules.findtime == "" {
		return nil, fmt.Errorf("Can't use empty bantime or fintime")
	}

	if config.rules.port[0] < 0 || config.rules.port[1] < config.rules.port[0] {
		return nil, fmt.Errorf("Your port configuration is bad, please change that")
	}

 	iplist, err := ImportIP(config.whitelist)
	if err != nil {
		return nil, err
	}
	whitelist := []ipChecking.Ip{}
	for _, v := range iplist {
		ip, err := ipChecking.BuildIp(v)
		if err != nil {
			Logger.Printf("Error: %s not valid", v)
			continue
		}
		whitelist = append(whitelist, ip)
	}

	iplist, err = ImportIP(config.blacklist)
	if err != nil {
		return nil, err
	}
	blacklist := []ipChecking.Ip{}
	for _, v := range iplist {
		ip, err := ipChecking.BuildIp(v)
		if err != nil {
			Logger.Printf("Error: %s not valid", v)
			continue
		}
		blacklist = append(blacklist, ip)
	}

	return &Fail2Ban{
		next:      next,
		name:      name,
		whitelist: whitelist,
		blacklist: blacklist,
		rules:     config.rules,
	}, nil
}

// Iterate over every headers to match the ones specified in the config and
// return nothing if regexp failed.
func (u *Fail2Ban) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	remoteIP := req.RemoteAddr
	// Whitelist
	for _, ip := range u.whitelist {
		if ip.CheckIpInSubnet(remoteIP) {
			u.next.ServeHTTP(rw, req)
			return
		}
	}
	// Blacklist
	for _, ip := range u.blacklist {
		if ip.CheckIpInSubnet(remoteIP) {
			Logger.Println(remoteIP + " is in the Blacklist")
			rw.WriteHeader(http.StatusForbidden)
			return
		}
	}
	//Fail2Ban
	ip := ipViewed[remoteIP]

	if reflect.DeepEqual(ip, IPViewed{}) {
		ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}
	} else {
		if ip.blacklisted {
			if time.Now().Before(ip.viewed.Add(u.rules.bantime)) {
				ipViewed[remoteIP] = IPViewed{ip.viewed, ip.nb + 1, true}
				Logger.Println(remoteIP + " is in the Blacklist")
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			ipViewed[remoteIP] = IPViewed{time.Now(), 1, false}
		} else if time.Now().Before(ip.viewed.Add(u.rules.findtime)) {
			if ip.nb+1 >= u.rules.maxretry {
				ipViewed[remoteIP] = IPViewed{ip.viewed, ip.nb + 1, true}
				Logger.Println(remoteIP + " is in the Blacklist")
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
