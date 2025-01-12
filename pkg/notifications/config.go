package notifications

type Config struct {
	Types    []string       `yaml:"allowedTypes"`
	Telegram TelegramConfig `yaml:"telegram"`
	Webhook  WebhookConfig  `yaml:"webhook"`
	Discord  DiscordConfig  `yaml:"discord"`
	Email    EmailConfig    `yaml:"email"`
}

type TemplateConfig struct {
	Ban    string `yaml:"ban"`
	Unban  string `yaml:"unban"`
	Notice string `yaml:"notice"`
}

type TelegramConfig struct {
	Enabled   bool           `yaml:"enabled"`
	BaseURL   string         `yaml:"baseUrl"`
	BotToken  string         `yaml:"botToken"`
	ChatID    string         `yaml:"chatId"`
	Templates TemplateConfig `yaml:"templates"`
}

type EmailConfig struct {
	Enabled   bool           `yaml:"enabled"`
	Server    string         `yaml:"server"`
	Port      int            `yaml:"port"`
	Username  string         `yaml:"username"`
	Password  string         `yaml:"password"`
	From      string         `yaml:"from"`
	To        string         `yaml:"to"`
	Templates TemplateConfig `yaml:"templates"`
}

type DiscordConfig struct {
	Enabled    bool           `yaml:"enabled"`
	WebhookURL string         `yaml:"webhookUrl"`
	Username   string         `yaml:"username"`
	AvatarURL  string         `yaml:"avatarUrl"`
	Templates  TemplateConfig `yaml:"templates"`
}

type WebhookConfig struct {
	Enabled   bool              `yaml:"enabled"`
	URL       string            `yaml:"url"`
	Method    string            `yaml:"method"`
	Headers   map[string]string `yaml:"headers"`
	Templates TemplateConfig    `yaml:"templates"`
}
