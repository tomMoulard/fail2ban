// Package notifications package provides a way to send notifications to different services.
package notifications

import (
	"log"
	"net/http"
	"time"
)

type notifier interface {
	Send(event Event) error
}
type Service struct {
	allowedTypes []string
	notifiers    []notifier
	ch           chan Event
}

func (s *Service) addNotifier(n notifier) {
	s.notifiers = append(s.notifiers, n)
}

func (s *Service) Notify(event Event) {
	for _, allowedType := range s.allowedTypes {
		if string(event.Type) == allowedType {
			s.ch <- event

			return
		}
	}
}

func (s *Service) Run() {
	for event := range s.ch {
		for _, n := range s.notifiers {
			if err := n.Send(event); err != nil {
				log.Printf("failed to send notification: %v", err)
			}
		}
	}
}

func NewService(cfg Config) *Service {
	allDisabled := !cfg.Telegram.Enabled && !cfg.Email.Enabled && !cfg.Webhook.Enabled && !cfg.Discord.Enabled

	if len(cfg.Types) == 0 || allDisabled {
		log.Printf("no notifiers enabled")

		return nil
	}
	// 1000 is large enough to handle typical traffic spikes but small enough to prevent unbounded memory growth
	const channelSize = 1000
	service := &Service{
		notifiers:    make([]notifier, 0),
		allowedTypes: cfg.Types,
		ch:           make(chan Event, channelSize),
	}

	const defaultHTTPTimeout = 10
	httpCli := &http.Client{
		Timeout: time.Second * defaultHTTPTimeout,
	}

	if cfg.Telegram.Enabled {
		tmpl := NewTemplateHandler(cfg.Telegram.Templates)
		n := NewTelegramNotifier(cfg.Telegram, tmpl, httpCli)
		service.addNotifier(n)
	}

	if cfg.Email.Enabled {
		tmpl := NewTemplateHandler(cfg.Email.Templates)
		n := NewEmailNotifier(cfg.Email, tmpl)
		service.addNotifier(n)
	}

	if cfg.Webhook.Enabled {
		tmpl := NewTemplateHandler(cfg.Webhook.Templates)
		n := NewWebhookNotifier(cfg.Webhook, tmpl, httpCli)
		service.addNotifier(n)
	}

	if cfg.Discord.Enabled {
		n := NewDiscordNotifier(cfg.Discord, httpCli)
		service.addNotifier(n)
	}

	return service
}
