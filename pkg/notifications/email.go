package notifications

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/smtp"
	"sync"
)

type mailer interface {
	Mail(from string) error
	Rcpt(to string) error
	Data() (io.WriteCloser, error)
	Noop() error
	Close() error
}

type EmailNotifier struct {
	server   string
	port     int
	username string
	password string
	from     string
	to       string
	subject  string

	client    mailer
	clientMux sync.Mutex
	templates *TemplateHandler
}

func NewEmailNotifier(cfg EmailConfig, templates *TemplateHandler) *EmailNotifier {
	n := &EmailNotifier{
		server:    cfg.Server,
		port:      cfg.Port,
		username:  cfg.Username,
		password:  cfg.Password,
		from:      cfg.From,
		to:        cfg.To,
		subject:   cfg.Subject,
		templates: templates,
	}

	return n
}

func (e *EmailNotifier) ensureConnected() error {
	e.clientMux.Lock()
	defer e.clientMux.Unlock()

	// Try to send a NOOP command to check if connection is still alive
	if e.client != nil {
		if err := e.client.Noop(); err == nil {
			return nil
		}
		// Connection is dead, close it
		_ = e.client.Close()
	}

	client, err := createSMTPClient(e.server, e.port, e.username, e.password)
	if err != nil {
		return fmt.Errorf("failed to reconnect SMTP client: %w", err)
	}

	e.client = client

	return nil
}

func (e *EmailNotifier) Send(event Event) error {
	// Ensure we have a valid connection
	if err := e.ensureConnected(); err != nil {
		return fmt.Errorf("failed to ensure SMTP connection: %w", err)
	}

	tmpl, err := e.templates.RenderTemplate(event)
	if err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}

	message := []byte(fmt.Sprintf("To: %s\r\n"+
		"From: %s\r\n"+
		"Subject: Fail2Ban Alert: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n", e.to, e.from, e.subject, tmpl))

	e.clientMux.Lock()
	defer e.clientMux.Unlock()

	if err = e.client.Mail(e.from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	if err = e.client.Rcpt(e.to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	w, err := e.client.Data()
	if err != nil {
		return fmt.Errorf("failed to create data writer: %w", err)
	}

	if _, err = w.Write(message); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err = w.Close(); err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return nil
}

func createSMTPClient(host string, port int, username, password string) (*smtp.Client, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	client, err := smtp.Dial(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SMTP server: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	if err = client.StartTLS(tlsConfig); err != nil {
		return nil, fmt.Errorf("failed to start TLS: %w", err)
	}

	auth := smtp.PlainAuth("", username, password, host)
	if err = client.Auth(auth); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	return client, nil
}
