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
	Bantime    string      `yaml:"bantime"`  // exprimate in a smart way: 3m
	Enabled    bool        `yaml:"enabled"`  // enable or disable the jail
	Findtime   string      `yaml:"findtime"` // exprimate in a smart way: 3m
	Maxretry   int         `yaml:"maxretry"`
	Urlregexps []Urlregexp `yaml:"urlregexps"`
	StatusCode string      `yaml:"statuscode"`
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

	var regexpAllow []*regexp.Regexp

	var regexpBan []*regexp.Regexp

	for _, rg := range r.Urlregexps {
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
		StatusCode:     r.StatusCode,
	}

	return rules, nil
}
