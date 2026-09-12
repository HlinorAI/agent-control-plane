package runtime

import (
	"strings"
	"testing"
	"time"
)

func TestReadEventsAndAggregate(t *testing.T) {
	input := `{"timestamp":"2026-01-02T03:04:05Z","request_id":"r1","agent_id":"a1","operation":"tool_call","target":"crm.search","provider":"crm","action":"read","success":true}
{"timestamp":"2026-01-02T03:05:05Z","request_id":"r2","agent_id":"a1","operation":"tool_call","target":"crm.write","provider":"crm","action":"write","success":false}
`
	events, skipped, err := ReadEvents(strings.NewReader(input), Options{})
	if err != nil {
		t.Fatalf("ReadEvents() error = %v", err)
	}
	report := Aggregate(events, skipped)
	if report.SchemaVersion != "runtime.v1" || report.EventsRead != 2 || len(report.Agents) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	summary := report.Agents[0]
	if summary.EventCount != 2 || summary.SuccessfulEvents != 1 || summary.FailedEvents != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(summary.Targets) != 2 || summary.Targets[0] != "crm.search" || summary.Targets[1] != "crm.write" {
		t.Fatalf("targets are not sorted: %+v", summary.Targets)
	}
}

func TestReadEventsRejectsPayloadAndInvalidEvent(t *testing.T) {
	input := `{"timestamp":"2026-01-02T03:04:05Z","operation":"tool_call","target":"crm.search","success":true}`
	if _, _, err := ReadEvents(strings.NewReader(input), Options{}); err == nil {
		t.Fatal("ReadEvents() accepted event without agent identity")
	}
}

func TestReadEventsLimit(t *testing.T) {
	input := `{"timestamp":"2026-01-02T03:04:05Z","agent_name":"support","operation":"tool_call","target":"crm.search","success":true}
{"timestamp":"2026-01-02T03:04:06Z","agent_name":"support","operation":"tool_call","target":"crm.search","success":true}
`
	_, _, err := ReadEvents(strings.NewReader(input), Options{MaxEvents: 1})
	if err == nil {
		t.Fatal("ReadEvents() did not enforce event limit")
	}
}

func TestAggregateUsesEarliestAndLatestTimestamp(t *testing.T) {
	events := []Event{
		{Timestamp: time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC), AgentName: "support", Operation: "tool_call", Target: "b", Success: true},
		{Timestamp: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC), AgentName: "support", Operation: "model_call", Target: "a", Success: true},
	}
	report := Aggregate(events, 0)
	if !report.Agents[0].FirstSeen.Before(report.Agents[0].LastSeen) {
		t.Fatalf("timestamps were not aggregated: %+v", report.Agents[0])
	}
}
