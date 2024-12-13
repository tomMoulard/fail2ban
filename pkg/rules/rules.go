// Package rules contains the rules for the fail2ban plugin.
package rules

import (
	"fmt"
	"log"
	"regexp"
	"time"
)

// Urlregexp struct.
type Urlregexp struct {
	Regexp string `yaml:"regexp"`
	Mode   string `yaml:"mode"`
}

// Rules struct fail2ban config.
type Rules struct {
	Bantime        string      `json:"bantime"        label:"Ban duration"            toml:"bantime"        yaml:"bantime"`
	Findtime       string      `json:"findtime"       label:"Detection window"        toml:"findtime"       yaml:"findtime"`
	MaxRetry       int         `json:"maxretry"       label:"Max retries before ban"  toml:"maxretry"       yaml:"maxretry"`
	Enabled        bool        `json:"enabled"        label:"Enable fail2ban"         toml:"enabled"        yaml:"enabled"`
	StatusCode     string      `json:"statuscode"     label:"Status codes to monitor" toml:"statuscode"     yaml:"statuscode"`
	URLRegexpBan   []string    `json:"urlregexpban"   label:"URLs to ban (regexp)"    toml:"urlregexpban"   yaml:"urlregexpban"`
	URLRegexpAllow []string    `json:"urlregexpallow" label:"URLs to allow (regexp)"  toml:"urlregexpallow" yaml:"urlregexpallow"`
	Urlregexps     []Urlregexp `json:"-"              toml:"-"                        yaml:"urlregexps"`
}

// RulesTransformed transformed Rules struct.
type RulesTransformed struct {
	Bantime        time.Duration
	Findtime       time.Duration
	URLRegexpAllow []*regexp.Regexp
	URLRegexpBan   []*regexp.Regexp
	MaxRetry       int
	Enabled        bool
	StatusCode     string
}

// TransformRule morph a Rules object into a RulesTransformed.
func TransformRule(r Rules) (RulesTransformed, error) {
	bantime, err := time.ParseDuration(r.Bantime)
	if err != nil {
		return RulesTransformed{}, fmt.Errorf("failed to parse bantime duration: %w", err)
	}

	findtime, err := time.ParseDuration(r.Findtime)
	if err != nil {
		return RulesTransformed{}, fmt.Errorf("failed to parse findtime duration: %w", err)
	}

	regexpAllow := make([]*regexp.Regexp, 0, len(r.URLRegexpAllow)+len(r.Urlregexps))
	regexpBan := make([]*regexp.Regexp, 0, len(r.URLRegexpBan)+len(r.Urlregexps))

	for _, pattern := range r.URLRegexpBan {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return RulesTransformed{}, fmt.Errorf("failed to compile ban regexp %q: %w", pattern, err)
		}

		regexpBan = append(regexpBan, re)
	}

	for _, pattern := range r.URLRegexpAllow {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return RulesTransformed{}, fmt.Errorf("failed to compile allow regexp %q: %w", pattern, err)
		}

		regexpAllow = append(regexpAllow, re)
	}

	for _, rg := range r.Urlregexps {
		if len(rg.Regexp) == 0 {
			continue
		}

		log.Println("Warning: using deprecated 'urlregexps' format, please use 'urlregexpban' and 'urlregexpallow' instead")

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
		MaxRetry:       r.MaxRetry,
		Enabled:        r.Enabled,
		StatusCode:     r.StatusCode,
	}

	return rules, nil
}
