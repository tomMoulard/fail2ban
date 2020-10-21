package fail2ban

import (
	"context"
	"net/http"
	"strings"

	"github.com/tommoulard/fail2ban/files"
)

// struct fail2ban config
type rules struct {
	ignorecommand     string `yaml:"igonecommand"`
	bantime           int64  `yaml:"bantime"`  //exprimate in second
	findtime          int64  `yaml:"findtime"` //exprimate in second
	maxretry          int    `yaml:"maxretry"`
	backend           string `yaml:"backend"`     //maybe we have to change this to another things or just delete it if its useless
	usedns            string `yaml:"usedns"`      //maybe change string by a int for limit the size (yes:0, warn:1, no:2, raw:3)
	logencoding       string `yaml:"logencoding"` //maybe useless for our project (utf-8, ascii)
	enabled           bool   `yaml:"enabled"`     //enable or disable the jail
	mode              string `yaml:"mode"`        //same than usedns
	filter            string `yaml:"filter"`      //= %(name)s[mode=%(mode)s] maybe change for a []string
	destemail         string `yaml:"destemail"`
	sender            string `yaml:"sender"`
	mta               string `yaml:"mta"`      //same than usedns
	protocol          string `yaml:"protocol"` //maybe int (tcp:0, udp:1)
	chain             string `yaml:"chain"`    //maybe useless because handle by traefik chain
	port              [2]int `yaml:"port"`
	fail2banAgent     string `yaml:"fail2ban_agent"`
	banaction         string `yaml:"banaction"`          //maybe useless because we are the firewall ?
	banactionAllports string `yaml:"banaction_allports"` //same as above
	actionAbuseipdb   string `yaml:"action_abuseipdb"`
	action            string `yaml:"action"` //maybe change for []string
}

type List struct {
	Ip    []string
	Files []string
}

type Config struct {
	blacklist List
	whitelist List
}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{}
}

// Fail2Ban holds the necessary components of a Traefik plugin
type Fail2Ban struct {
	next      http.Handler
	name      string
	whitelist []string
	blacklist []string
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
    rlist = append(rlist, list.Ip...)
	return rlist, nil
}

// New instantiates and returns the required components used to handle a HTTP request
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	whitelist, err := ImportIP(config.whitelist)
	if err != nil {
		return nil, err
	}

	blacklist, err := ImportIP(config.blacklist)
	if err != nil {
		return nil, err
	}

	return &Fail2Ban{
		next:      next,
		name:      name,
		whitelist: whitelist,
		blacklist: blacklist,
	}, nil
}

// Iterate over every headers to match the ones specified in the config and
// return nothing if regexp failed.
func (u *Fail2Ban) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Write([]byte("cdjscl,dcle,c\n"))
	u.next.ServeHTTP(rw, req)
}
