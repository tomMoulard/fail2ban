package htransformation

import (
	"context"
	"net/http"
)

// Config holds configuration to be passed to the plugin
type Config struct{}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{}
}

// Fail2Ban holds the necessary components of a Traefik plugin
type Fail2Ban struct {
	next http.Handler
	name string
}

// New instantiates and returns the required components used to handle a HTTP request
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Fail2Ban{
		next: next,
		name: name,
	}, nil
}

// Iterate over every headers to match the ones specified in the config and
// return nothing if regexp failed.
func (u *Fail2Ban) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	u.next.ServeHTTP(rw, req)
}
