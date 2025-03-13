package notifications

import "time"

type EventType string

const (
	EventTypeBan    EventType = "ban"
	EventTypeUnban  EventType = "unban"
	EventTypeNotice EventType = "notice"
)

type Event struct {
	Type      EventType
	IP        string
	Message   string
	Timestamp time.Time
	Duration  time.Duration
}

func BanEvent(ip, message string, duration time.Duration) Event {
	return Event{
		Type:      EventTypeBan,
		IP:        ip,
		Message:   message,
		Timestamp: time.Now(),
		Duration:  duration,
	}
}

func UnbanEvent(ip, message string) Event {
	return Event{
		Type:      EventTypeUnban,
		IP:        ip,
		Message:   message,
		Timestamp: time.Now(),
	}
}
