package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type DiscordWebhookPayload struct {
	Username  string         `json:"username"`
	AvatarURL string         `json:"avatarUrl"`
	Content   string         `json:"content"`
	Embeds    []DiscordEmbed `json:"embeds"`
}

type DiscordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []DiscordField `json:"fields"`
	Timestamp   string         `json:"timestamp"`
}

type DiscordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type DiscordNotifier struct {
	webhookURL string
	username   string
	title      string
	avatarURL  string
	httpCli    *http.Client
}

func NewDiscordNotifier(cfg DiscordConfig, httpCli *http.Client) *DiscordNotifier {
	return &DiscordNotifier{
		webhookURL: cfg.WebhookURL,
		username:   cfg.Username,
		title:      cfg.Title,
		avatarURL:  cfg.AvatarURL,
		httpCli:    httpCli,
	}
}

//nolint:noctx
func (d *DiscordNotifier) Send(event Event) error {
	var color int

	switch event.Type {
	case EventTypeBan:
		color = 16711680 // Red
	case EventTypeUnban:
		color = 65280 // Green
	case EventTypeNotice:
		color = 16777215
	}

	payload := DiscordWebhookPayload{
		Username:  d.username,
		AvatarURL: d.avatarURL,
		Embeds: []DiscordEmbed{
			{
				Title:       d.title,
				Description: event.Message,
				Color:       color,
				Fields: []DiscordField{
					{
						Name:   "IP Address",
						Value:  event.IP,
						Inline: true,
					},
					{
						Name:   "Ban Duration",
						Value:  event.Duration.String(),
						Inline: true,
					},
				},
				Timestamp: event.Timestamp.Format(time.RFC3339),
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal discord payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, d.webhookURL, bytes.NewReader(jsonPayload))
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
