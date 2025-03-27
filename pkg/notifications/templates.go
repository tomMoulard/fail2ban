package notifications

import (
	"bytes"
	"fmt"
	"log"
	"text/template"
)

const (
	DefaultBanTemplate = `🚫 IP Ban Alert
IP: {{.IP}}
Reason: {{.Message}}
Time: {{.Timestamp.Format "2006-01-02 15:04:05"}}
Duration: {{.Duration}}`

	DefaultUnbanTemplate = `✅ IP Unban Alert
IP: {{.IP}}
Reason: {{.Message}}
Time: {{.Timestamp.Format "2006-01-02 15:04:05"}}`

	DefaultNoticeTemplate = `ℹ️ Notice
IP: {{.IP}}
Message: {{.Message}}
Time: {{.Timestamp.Format "2006-01-02 15:04:05"}}`
)

var defaultTemplatesMapping = map[EventType]string{
	EventTypeBan:    DefaultBanTemplate,
	EventTypeUnban:  DefaultUnbanTemplate,
	EventTypeNotice: DefaultNoticeTemplate,
}

type TemplateHandler struct {
	templates map[EventType]*template.Template
}

func NewTemplateHandler(cfg TemplateConfig) *TemplateHandler {
	templates := make(map[EventType]*template.Template)

	templates[EventTypeBan] = makeTmplOrDefault(EventTypeBan, cfg.Ban)
	templates[EventTypeUnban] = makeTmplOrDefault(EventTypeUnban, cfg.Unban)
	templates[EventTypeNotice] = makeTmplOrDefault(EventTypeNotice, cfg.Notice)

	return &TemplateHandler{
		templates: templates,
	}
}

func makeTmplOrDefault(tp EventType, tmpl string) *template.Template {
	if tmpl == "" {
		log.Printf("no template provided for %s, using default", tp)
		tmpl = defaultTemplatesMapping[tp]
	}

	t, err := template.New(string(tp)).Parse(tmpl)
	if err != nil {
		log.Printf("failed to parse %s template: %v", tp, err)

		return nil
	}

	return t
}

func (th *TemplateHandler) RenderTemplate(event Event) (string, error) {
	tmpl, ok := th.templates[event.Type]
	if !ok {
		return "", fmt.Errorf("no template found for %s", event.Type)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, event); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}
