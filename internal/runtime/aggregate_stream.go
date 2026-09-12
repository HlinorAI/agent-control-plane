package runtime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// AggregateReader consumes JSONL one event at a time and does not retain the input events.
func AggregateReader(r io.Reader, options Options) (Report, error) {
	options = options.withDefaults()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), options.MaxLineBytes)
	state := newAggregateState()
	line := 0
	for scanner.Scan() {
		line++
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		if state.eventsRead >= options.MaxEvents {
			return Report{}, fmt.Errorf("runtime event limit exceeded: %d", options.MaxEvents)
		}
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return Report{}, fmt.Errorf("decode runtime event %d: %w", line, err)
		}
		if err := validateEvent(event); err != nil {
			return Report{}, fmt.Errorf("validate runtime event %d: %w", line, err)
		}
		state.add(event)
	}
	if err := scanner.Err(); err != nil {
		return Report{}, fmt.Errorf("read runtime events: %w", err)
	}
	return state.report(), nil
}

type aggregateState struct {
	eventsRead int
	byKey      map[string]*AgentSummary
}

func newAggregateState() *aggregateState {
	return &aggregateState{byKey: make(map[string]*AgentSummary)}
}

func (s *aggregateState) add(event Event) {
	s.eventsRead++
	key := event.AgentID
	if key == "" {
		key = "name:" + event.AgentName
	}
	summary := s.byKey[key]
	if summary == nil {
		summary = &AgentSummary{AgentID: event.AgentID, AgentName: event.AgentName, FirstSeen: event.Timestamp, LastSeen: event.Timestamp, Operations: make(map[string]int)}
		s.byKey[key] = summary
	}
	addEvent(summary, event)
}

func (s *aggregateState) report() Report {
	agents := make([]AgentSummary, 0, len(s.byKey))
	for _, summary := range s.byKey {
		normalizeSummary(summary)
		agents = append(agents, *summary)
	}
	sortSummaries(agents)
	return Report{SchemaVersion: "runtime.v1", EventsRead: s.eventsRead, Agents: agents}
}
