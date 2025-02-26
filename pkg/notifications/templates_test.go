package notifications

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		cfg           TemplateConfig
		event         Event
		expectedError bool
		contains      string
	}{
		{
			name: "default ban template",
			event: Event{
				Type:      EventTypeBan,
				IP:        "192.0.2.1",
				Message:   "test ban",
				Timestamp: time.Now(),
				Duration:  time.Hour,
			},
			contains: "🚫 IP Ban Alert",
		},
		{
			name: "custom ban template",
			cfg: TemplateConfig{
				Ban: "Custom Ban: {{.IP}}",
			},
			event: Event{
				Type:      EventTypeBan,
				IP:        "192.0.2.1",
				Message:   "test ban",
				Timestamp: time.Now(),
				Duration:  time.Hour,
			},
			contains: "Custom Ban: 192.0.2.1",
		},
		{
			name: "invalid template",
			cfg: TemplateConfig{
				Ban: "{{.InvalidField}}",
			},
			event: Event{
				Type: EventTypeBan,
			},
			expectedError: true,
		},
		{
			name: "empty event message",
			event: Event{
				Type:      EventTypeBan,
				IP:        "192.0.2.1",
				Message:   "",
				Timestamp: time.Now(),
			},
			contains: "IP: 192.0.2.1",
		},
		{
			name: "nil timestamp",
			event: Event{
				Type:    EventTypeBan,
				IP:      "192.0.2.1",
				Message: "test",
			},
			expectedError: false,
		},
		{
			name: "template with complex formatting",
			cfg: TemplateConfig{
				Ban: "{{if .Message}}{{.Message}}{{else}}No message{{end}}",
			},
			event: Event{
				Type:      EventTypeBan,
				IP:        "192.0.2.1",
				Timestamp: time.Now(),
			},
			contains: "No message",
		},
		{
			name: "unknown event type",
			event: Event{
				Type: "unknown",
			},
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			th := NewTemplateHandler(test.cfg)
			result, err := th.RenderTemplate(test.event)

			if test.expectedError {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Contains(t, result, test.contains)
		})
	}
}
