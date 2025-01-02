// Package rules contains the rules for the fail2ban plugin.
package rules

import (
	"fmt"
	"regexp"
	"time"
)

// Urlregexp struct.
type Urlregexp struct {
	Regexp string `json:"regexp" toml:"regexp" yaml:"regexp"`
	Mode   string `json:"mode"   toml:"mode"   yaml:"mode"`
}

// Rules struct fail2ban config.
type Rules struct {
	Bantime    string      `json:"bantime"    label:"Ban duration"            toml:"bantime"    yaml:"bantime"`
	Findtime   string      `json:"findtime"   label:"Detection window"        toml:"findtime"   yaml:"findtime"`
	MaxRetry   int         `json:"maxretry"   label:"Max retries before ban"  toml:"maxretry"   yaml:"maxretry"`
	Enabled    bool        `json:"enabled"    label:"Enable fail2ban"         toml:"enabled"    yaml:"enabled"`
	StatusCode string      `json:"statuscode" label:"Status codes to monitor" toml:"statuscode" yaml:"statuscode"`
	Urlregexps []Urlregexp `json:"urlregexps" label:"URL regexps"             toml:"urlregexps" yaml:"urlregexps"`
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

	regexpAllow := make([]*regexp.Regexp, 0, len(r.Urlregexps))
	regexpBan := make([]*regexp.Regexp, 0, len(r.Urlregexps))

	for _, rg := range r.Urlregexps {
		if len(rg.Regexp) == 0 {
			continue
		}

		fmt.Printf("Warning: using deprecated 'urlregexps' format, please use 'urlregexpban' and 'urlregexpallow' instead\n")

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
			fmt.Printf("mode %q is not known, the rule %q cannot not be applied\n", rg.Mode, rg.Regexp)
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
