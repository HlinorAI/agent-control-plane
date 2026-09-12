package runtime

import (
	"reflect"
	"strings"
	"testing"
)

func TestAggregateReaderMatchesAggregate(t *testing.T) {
	input := strings.NewReader(`{"timestamp":"2026-01-02T03:04:05Z","agent_id":"a1","operation":"tool_call","target":"crm.search","provider":"crm","success":true}
{"timestamp":"2026-01-02T03:05:05Z","agent_id":"a1","environment":"production","operation":"tool_call","target":"crm.write","provider":"crm","action":"write","success":false}
`)
	events, skipped, err := ReadEvents(strings.NewReader(`{"timestamp":"2026-01-02T03:04:05Z","agent_id":"a1","operation":"tool_call","target":"crm.search","provider":"crm","success":true}
{"timestamp":"2026-01-02T03:05:05Z","agent_id":"a1","environment":"production","operation":"tool_call","target":"crm.write","provider":"crm","action":"write","success":false}
`), Options{})
	if err != nil {
		t.Fatalf("ReadEvents() error = %v", err)
	}
	streamed, err := AggregateReader(input, Options{})
	if err != nil {
		t.Fatalf("AggregateReader() error = %v", err)
	}
	if expected := Aggregate(events, skipped); !reflect.DeepEqual(streamed, expected) {
		t.Fatalf("streaming report differs\nstreamed=%+v\nexpected=%+v", streamed, expected)
	}
}

func TestAggregateReaderEnforcesEventLimit(t *testing.T) {
	input := strings.NewReader(`{"timestamp":"2026-01-02T03:04:05Z","agent_id":"a1","operation":"tool_call","target":"crm.search","success":true}
{"timestamp":"2026-01-02T03:05:05Z","agent_id":"a1","operation":"tool_call","target":"crm.search","success":true}
`)
	if _, err := AggregateReader(input, Options{MaxEvents: 1}); err == nil {
		t.Fatal("AggregateReader() did not enforce event limit")
	}
}
