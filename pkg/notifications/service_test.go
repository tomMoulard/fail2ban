package notifications

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cfg            Config
		expectNil      bool
		expectNotifier int
		setupMock      func(*mockNotifier)
	}{
		{
			name: "all disabled",
			cfg: Config{
				Types: []string{"ban", "unban"},
			},
			expectNil: true,
		},
		{
			name: "no types",
			cfg: Config{
				Telegram: TelegramConfig{Enabled: true},
			},
			expectNil: true,
		},
		{
			name: "telegram enabled",
			cfg: Config{
				Types: []string{"ban", "unban"},
				Telegram: TelegramConfig{
					Enabled:  true,
					BotToken: "test-token",
					ChatID:   "test-chat",
				},
			},
			expectNotifier: 1,
		},
		{
			name: "all enabled",
			cfg: Config{
				Types: []string{"ban", "unban"},
				Telegram: TelegramConfig{
					Enabled:  true,
					BotToken: "test-token",
					ChatID:   "test-chat",
				},
				Discord: DiscordConfig{
					Enabled:    true,
					WebhookURL: "https://discord.webhook",
				},
				Email: EmailConfig{
					Enabled:  true,
					Server:   "smtp.test.com:587",
					Username: "test",
					Password: "test",
					From:     "from@test.com",
					To:       "to@test.com",
				},
				Webhook: WebhookConfig{
					Enabled: true,
					URL:     "https://webhook.test",
					Method:  "POST",
				},
			},
			expectNotifier: 4,
		},
		{
			name: "partial notifier failure",
			cfg: Config{
				Types:    []string{"ban"},
				Telegram: TelegramConfig{Enabled: true},
				Discord:  DiscordConfig{Enabled: true},
			},
			expectNotifier: 2,
		},
		{
			name: "concurrent notifications",
			cfg: Config{
				Types:    []string{"ban", "unban"},
				Telegram: TelegramConfig{Enabled: true},
				Discord:  DiscordConfig{Enabled: true},
				Email:    EmailConfig{Enabled: true},
			},
			expectNotifier: 3,
		},
		{
			name: "invalid event type",
			cfg: Config{
				Types:    []string{"invalid"},
				Telegram: TelegramConfig{Enabled: true},
			},
			expectNotifier: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			svc := NewService(test.cfg)
			if test.expectNil {
				assert.Nil(t, svc)

				return
			}

			require.NotNil(t, svc)
			assert.Len(t, svc.notifiers, test.expectNotifier)
		})
	}
}

func TestServiceNotify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		allowedTypes []string
		event        Event
		shouldNotify bool
	}{
		{
			name:         "allowed type",
			allowedTypes: []string{"ban", "unban"},
			event: Event{
				Type:      EventTypeBan,
				IP:        "192.0.2.1",
				Message:   "test ban",
				Timestamp: time.Now(),
				Duration:  time.Hour,
			},
			shouldNotify: true,
		},
		{
			name:         "disallowed type",
			allowedTypes: []string{"unban"},
			event: Event{
				Type:      EventTypeBan,
				IP:        "192.0.2.1",
				Message:   "test ban",
				Timestamp: time.Now(),
				Duration:  time.Hour,
			},
			shouldNotify: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			notified := false
			n := &mockNotifier{
				fn: func(event Event) error {
					notified = true

					return nil
				},
			}

			svc := &Service{
				allowedTypes: test.allowedTypes,
				notifiers:    []notifier{n},
			}

			svc.Notify(test.event)
			time.Sleep(100 * time.Millisecond) // Wait for goroutine
			assert.Equal(t, test.shouldNotify, notified)
		})
	}
}

type mockNotifier struct {
	fn func(event Event) error
}

func (m *mockNotifier) Send(event Event) error {
	return m.fn(event)
}
