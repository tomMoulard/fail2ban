package notifications

import (
	"net/smtp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockMailer struct {
	err bool
}

func (m *mockMailer) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	if m.err {
		return assert.AnError
	}

	return nil
}

func TestEmailNotifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      EmailConfig
		expectError bool
	}{
		{
			name: "valid configuration",
			config: EmailConfig{
				Server:   "smtp.test.com:587",
				Username: "test@test.com",
				Password: "password",
				From:     "from@test.com",
				To:       "to@test.com",
			},
			expectError: false,
		},
		{
			name: "error case",
			config: EmailConfig{
				Server:   "invalid-server:8080",
				Username: "test@test.com",
				Password: "password",
				From:     "from@test.com",
				To:       "to@test.com",
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			n := NewEmailNotifier(test.config, NewTemplateHandler(TemplateConfig{}))
			n.cli = &mockMailer{
				err: test.expectError,
			}
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
