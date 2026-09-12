package runtime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

type Options struct {
	MaxLineBytes int
	MaxEvents    int
}

func (o Options) withDefaults() Options {
	if o.MaxLineBytes <= 0 {
		o.MaxLineBytes = DefaultMaxLineBytes
	}
	if o.MaxEvents <= 0 {
		o.MaxEvents = DefaultMaxEvents
	}
	return o
}

func ReadEvents(r io.Reader, options Options) ([]Event, int, error) {
	options = options.withDefaults()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), options.MaxLineBytes)
	events := make([]Event, 0)
	skipped := 0
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 || strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		if len(events) >= options.MaxEvents {
			return nil, skipped, fmt.Errorf("runtime event limit exceeded: %d", options.MaxEvents)
		}
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, skipped, fmt.Errorf("decode runtime event %d: %w", len(events)+skipped+1, err)
		}
		if err := validateEvent(event); err != nil {
			return nil, skipped, fmt.Errorf("validate runtime event %d: %w", len(events)+skipped+1, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, skipped, fmt.Errorf("read runtime events: %w", err)
	}
	return events, skipped, nil
}

func validateEvent(event Event) error {
	if event.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	if event.Timestamp.After(time.Now().Add(5 * time.Minute)) {
		return fmt.Errorf("timestamp is in the future")
	}
	if strings.TrimSpace(event.AgentID) == "" && strings.TrimSpace(event.AgentName) == "" {
		return fmt.Errorf("agent_id or agent_name is required")
	}
	if strings.TrimSpace(event.Operation) == "" {
		return fmt.Errorf("operation is required")
	}
	if strings.TrimSpace(event.Target) == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}
