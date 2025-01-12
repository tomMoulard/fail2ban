package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type TelegramNotifier struct {
	botToken string
	chatID   string
	baseURL  string

	httpCli   *http.Client
	templates *TemplateHandler
}

func NewTelegramNotifier(cfg TelegramConfig, templates *TemplateHandler, httpCli *http.Client) *TelegramNotifier {
	tn := TelegramNotifier{
		botToken:  cfg.BotToken,
		chatID:    cfg.ChatID,
		baseURL:   cfg.BaseURL,
		httpCli:   httpCli,
		templates: templates,
	}
	if tn.baseURL == "" {
		tn.baseURL = "https://api.telegram.org"
	}

	return &tn
}

//nolint:noctx
func (t *TelegramNotifier) Send(event Event) error {
	msg, err := t.templates.RenderTemplate(event)
	if err != nil {
		return fmt.Errorf("failed to render telegram template: %w", err)
	}

	url := fmt.Sprintf("%s/bot%s/sendMessage", t.baseURL, t.botToken)
	payload := map[string]string{
		"chat_id":    t.chatID,
		"text":       msg,
		"parse_mode": "HTML",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create telegram request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpCli.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send telegram message: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status code %d", resp.StatusCode)
	}

	return nil
}
