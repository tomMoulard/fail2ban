package notifications

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDiscordNotifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		serverResponse int
		expectError    bool
		config         DiscordConfig
	}{
		{
			name:           "successful notification",
			serverResponse: http.StatusOK,
			expectError:    false,
			config: DiscordConfig{
				WebhookURL: "https://discord.webhook",
				Username:   "TestBot",
				AvatarURL:  "https://test.com/avatar.png",
			},
		},
		{
			name:           "server error",
			serverResponse: http.StatusInternalServerError,
			expectError:    true,
			config: DiscordConfig{
				WebhookURL: "https://discord.webhook",
			},
		},
		{
			name:           "invalid webhook URL",
			serverResponse: http.StatusBadRequest,
			expectError:    true,
			config: DiscordConfig{
				WebhookURL: "invalid-url",
			},
		},
		{
			name:           "empty webhook URL",
			serverResponse: http.StatusBadRequest,
			expectError:    true,
			config: DiscordConfig{
				WebhookURL: "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
				w.WriteHeader(test.serverResponse)
			}))
			defer server.Close()

			test.config.WebhookURL = server.URL
			n := NewDiscordNotifier(test.config, server.Client())

			err := n.Send(Event{
				Type:      EventTypeBan,
				IP:        "192.0.2.1",
				Message:   "test",
				Timestamp: time.Now(),
			})

			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
