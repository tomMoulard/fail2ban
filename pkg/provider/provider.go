// Package provider contains the provider for the plugin.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/traefik/genconf/dynamic"
)

// Config the plugin configuration.
type Config struct {
	PollInterval string `json:"pollInterval,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		PollInterval: "5s",
	}
}

// Provider a simple provider plugin.
type Provider struct {
	name         string
	pollInterval time.Duration
	handler      http.Handler
	cancel       func()
}

// New creates a new Provider plugin.
func New(ctx context.Context, config *Config, handler http.Handler, name string) (*Provider, error) {
	pi, err := time.ParseDuration(config.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid poll interval duration: %w", err)
	}

	return &Provider{
		name:         name,
		pollInterval: pi,
		handler:      handler,
	}, nil
}

// Init the provider.
func (p *Provider) Init() error {
	if p.pollInterval <= 0 {
		return errors.New("poll interval must be greater than 0")
	}

	return nil
}

// Provide creates and sends dynamic configuration.
func (p *Provider) Provide(cfgChan chan<- json.Marshaler) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	go func() {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("Failed to provide configuration: %v\n", err)
			}
		}()
		p.loadConfiguration(ctx, cfgChan)
	}()

	return nil
}

func (p *Provider) loadConfiguration(ctx context.Context, cfgChan chan<- json.Marshaler) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			configuration := p.generateConfiguration()
			cfgChan <- &dynamic.JSONPayload{Configuration: configuration}
		case <-ctx.Done():
			return
		}
	}
}

// Stop to stop the provider and the related go routines.
func (p *Provider) Stop() error {
	p.cancel()

	return nil
}

func (p *Provider) generateConfiguration() *dynamic.Configuration {
	configuration := &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers:  make(map[string]*dynamic.Router),
			Services: make(map[string]*dynamic.Service),
		},
	}

	configuration.HTTP.Routers["fail2ban-dashboard"] = &dynamic.Router{
		EntryPoints: []string{"traefik"},
		Service:     "fail2ban-dashboard",
		Rule:        "PathPrefix(`/fail2ban`)",
		Middlewares: []string{"fail2ban-strip-prefix"},
	}

	configuration.HTTP.Services["fail2ban-dashboard"] = &dynamic.Service{
		LoadBalancer: &dynamic.ServersLoadBalancer{
			Servers: []dynamic.Server{
				{
					URL: "http://internal",
				},
			},
			PassHostHeader: boolPtr(true),
		},
	}

	configuration.HTTP.Middlewares = map[string]*dynamic.Middleware{
		"fail2ban-strip-prefix": {
			StripPrefix: &dynamic.StripPrefix{
				Prefixes: []string{"/fail2ban"},
			},
		},
	}

	return configuration
}

func boolPtr(v bool) *bool {
	return &v
}
