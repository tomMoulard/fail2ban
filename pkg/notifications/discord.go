package notifications

import (
	"fmt"
	"net/http"
	"strings"
)

type DiscordNotifier struct {
	webhookURL string
	username   string
	avatarURL  string
	httpCli    *http.Client
	templates  *TemplateHandler
}

func NewDiscordNotifier(cfg DiscordConfig, templates *TemplateHandler, httpCli *http.Client) *DiscordNotifier {
	return &DiscordNotifier{
		webhookURL: cfg.WebhookURL,
		username:   cfg.Username,
		avatarURL:  cfg.AvatarURL,
		httpCli:    httpCli,
		templates:  templates,
	}
}

//nolint:noctx
func (d *DiscordNotifier) Send(event Event) error {
	jsonPayload, err := d.templates.RenderTemplate(event)
	if err != nil {
		return fmt.Errorf("failed to render discord template: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, d.webhookURL, strings.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create discord request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpCli.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send discord webhook: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("discord webhook returned status: %d", resp.StatusCode)
	}

	return nil
}
