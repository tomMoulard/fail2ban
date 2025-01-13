package notifications

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEventCreation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fn       func() Event
		expected EventType
	}{
		{
			name: "ban event",
			fn: func() Event {
				return BanEvent("192.0.2.1", "test ban", time.Hour)
			},
			expected: EventTypeBan,
		},
		{
			name: "unban event",
			fn: func() Event {
				return UnbanEvent("192.0.2.1", "test unban")
			},
			expected: EventTypeUnban,
		},
		{
			name: "notice event",
			fn: func() Event {
				return Event{
					Type:    EventTypeNotice,
					IP:      "192.0.2.1",
					Message: "test notice",
				}
			},
			expected: EventTypeNotice,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			event := test.fn()
			assert.Equal(t, test.expected, event.Type)
			assert.NotEmpty(t, event.IP)
			assert.NotEmpty(t, event.Message)

			if event.Type == EventTypeBan {
				assert.NotZero(t, event.Duration)
			}

			if event.Type != EventTypeNotice {
				assert.NotZero(t, event.Timestamp)
			}
		})
	}
}
