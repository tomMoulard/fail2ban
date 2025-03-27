package notifications

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTelegramNotifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		serverResponse int
		expectError    bool
	}{
		{
			name:           "successful notification",
			serverResponse: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "server error",
			serverResponse: http.StatusInternalServerError,
			expectError:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.serverResponse)
			}))
			defer server.Close()
			n := NewTelegramNotifier(TelegramConfig{
				BotToken: "test-token",
				ChatID:   "test-chat",
				BaseURL:  server.URL,
			}, NewTemplateHandler(TemplateConfig{}), server.Client())

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
