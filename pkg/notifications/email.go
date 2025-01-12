package notifications

import (
	"fmt"
	"net/smtp"
)

type mailer interface {
	SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

type defaultMailer struct{}

//nolint:wrapcheck
func (d *defaultMailer) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return smtp.SendMail(addr, a, from, to, msg)
}

type EmailNotifier struct {
	server   string
	username string
	password string
	from     string
	to       string

	cli       mailer
	templates *TemplateHandler
}

func NewEmailNotifier(cfg EmailConfig, templates *TemplateHandler) *EmailNotifier {
	return &EmailNotifier{
		server:    cfg.Server,
		username:  cfg.Username,
		password:  cfg.Password,
		from:      cfg.From,
		to:        cfg.To,
		cli:       &defaultMailer{},
		templates: templates,
	}
}

func (e *EmailNotifier) Send(event Event) error {
	auth := smtp.PlainAuth("", e.from, e.password, e.server)

	tmpl, err := e.templates.RenderTemplate(event)
	if err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}

	msg := fmt.Sprintf("To: %s\r\n"+
		"From: %s\r\n"+
		"Subject: Fail2Ban Alert: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n", e.to, e.from, event.Type, tmpl)

	err = e.cli.SendMail(e.server, auth, e.from, []string{e.to}, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
