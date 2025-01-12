package notifications

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWebhookNotifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		serverResponse int
		expectError    bool
		config         WebhookConfig
	}{
		{
			name:           "successful POST notification",
			serverResponse: http.StatusOK,
			expectError:    false,
			config: WebhookConfig{
				URL:     "https://webhook.test",
				Method:  "POST",
				Headers: map[string]string{"X-Custom": "test"},
			},
		},
		{
			name:           "successful GET notification",
			serverResponse: http.StatusOK,
			expectError:    false,
			config: WebhookConfig{
				URL:    "https://webhook.test",
				Method: "GET",
			},
		},
		{
			name:           "server error",
			serverResponse: http.StatusInternalServerError,
			expectError:    true,
			config: WebhookConfig{
				URL:    "https://webhook.test",
				Method: "POST",
			},
		},
		{
			name:           "invalid method",
			serverResponse: http.StatusBadRequest,
			expectError:    true,
			config: WebhookConfig{
				URL:    "https://webhook.test",
				Method: "INVALID",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.config.Method, r.Method)

				for k, v := range test.config.Headers {
					assert.Equal(t, v, r.Header.Get(k))
				}

				w.WriteHeader(test.serverResponse)
			}))
			defer server.Close()

			test.config.URL = server.URL
			notifier := NewWebhookNotifier(test.config, NewTemplateHandler(TemplateConfig{}), server.Client())

			err := notifier.Send(Event{
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
