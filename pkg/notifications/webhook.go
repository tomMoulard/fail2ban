package notifications

import (
	"fmt"
	"net/http"
	"strings"
)

type WebhookNotifier struct {
	url       string
	method    string
	headers   map[string]string
	httpCli   *http.Client
	templates *TemplateHandler
}

func NewWebhookNotifier(cfg WebhookConfig, templates *TemplateHandler, httpCli *http.Client) *WebhookNotifier {
	return &WebhookNotifier{
		url:       cfg.URL,
		method:    cfg.Method,
		headers:   cfg.Headers,
		httpCli:   httpCli,
		templates: templates,
	}
}

//nolint:noctx
func (w *WebhookNotifier) Send(event Event) error {
	payload, err := w.templates.RenderTemplate(event)
	if err != nil {
		return fmt.Errorf("failed to render webhook template: %w", err)
	}

	req, err := http.NewRequest(w.method, w.url, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fail2Ban-Notifier")

	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.httpCli.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("webhook request failed with status: %d", resp.StatusCode)
	}

	return nil
}
