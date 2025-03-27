package notifications

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockMailer struct {
	sendErr error
	noopErr error
	closed  bool
}

func (m *mockMailer) Close() error {
	m.closed = true

	return nil
}

func (m *mockMailer) Noop() error {
	return m.noopErr
}

func (m *mockMailer) Mail(from string) error {
	if m.sendErr != nil {
		return m.sendErr
	}

	return nil
}

func (m *mockMailer) Rcpt(to string) error {
	if m.sendErr != nil {
		return m.sendErr
	}

	return nil
}

func (m *mockMailer) Data() (io.WriteCloser, error) {
	if m.sendErr != nil {
		return nil, m.sendErr
	}

	return &mockWriteCloser{}, nil
}

type mockWriteCloser struct{}

func (m *mockWriteCloser) Write(p []byte) (int, error) {
	return len(p), nil
}

func (m *mockWriteCloser) Close() error {
	return nil
}

func TestEmailNotifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      EmailConfig
		event       Event
		setupMock   func(*mockMailer)
		expectError bool
		validate    func(*testing.T, *EmailNotifier)
	}{
		{
			name: "valid configuration",
			config: EmailConfig{
				Server:   "smtp.test.com",
				Port:     587,
				Username: "test@test.com",
				Password: "password",
				From:     "from@test.com",
				To:       "to@test.com",
			},
			event: Event{
				Type:      EventTypeBan,
				IP:        "192.0.2.1",
				Message:   "test ban",
				Timestamp: time.Now(),
				Duration:  time.Hour,
			},
		},
		{
			name: "concurrent connections",
			config: EmailConfig{
				Server: "smtp.test.com",
				Port:   587,
				From:   "from@test.com",
				To:     "to@test.com",
			},
			validate: func(t *testing.T, n *EmailNotifier) {
				t.Helper()
				// Send multiple emails concurrently
				errCh := make(chan error, 3)
				for range 3 {
					go func() {
						errCh <- n.Send(Event{
							Type:      EventTypeBan,
							IP:        "192.0.2.1",
							Message:   "test ban",
							Timestamp: time.Now(),
						})
					}()
				}

				// Check results
				for range 3 {
					err := <-errCh
					assert.NoError(t, err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// Create mock mailer
			mock := &mockMailer{}
			if test.setupMock != nil {
				test.setupMock(mock)
			}

			// Create notifier
			n := &EmailNotifier{
				server:   test.config.Server,
				port:     test.config.Port,
				username: test.config.Username,
				password: test.config.Password,
				from:     test.config.From,
				to:       test.config.To,
				subject:  test.config.Subject,
				client:   mock,
				templates: NewTemplateHandler(TemplateConfig{
					Ban:    DefaultBanTemplate,
					Unban:  DefaultUnbanTemplate,
					Notice: DefaultNoticeTemplate,
				}),
			}

			// If no event is specified in test case, use default
			if test.event == (Event{}) {
				test.event = Event{
					Type:      EventTypeBan,
					IP:        "192.0.2.1",
					Message:   "test",
					Timestamp: time.Now(),
				}
			}

			// Send notification
			err := n.Send(test.event)

			// Validate results
			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// Run additional validations if specified
			if test.validate != nil {
				test.validate(t, n)
			}
		})
	}
}

func TestEmailNotifier_Creation(t *testing.T) {
	t.Parallel()

	config := EmailConfig{
		Server:   "smtp.test.com",
		Port:     587,
		Username: "test@test.com",
		Password: "password",
		From:     "from@test.com",
		To:       "to@test.com",
	}

	n := NewEmailNotifier(config, NewTemplateHandler(TemplateConfig{}))

	assert.NotNil(t, n)
}
