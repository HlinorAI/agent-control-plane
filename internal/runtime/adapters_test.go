package runtime

import (
	"strings"
	"testing"
)

func TestReadOTelJSON(t *testing.T) {
	input := `{"resourceSpans":[{"resource":{"attributes":[{"key":"deployment.environment","value":{"stringValue":"production"}}]},"scopeSpans":[{"spans":[{"traceId":"trace-1","name":"crm.search","startTime":"2026-01-02T03:04:05Z","status":{"code":"OK"},"attributes":[{"key":"agent.id","value":{"stringValue":"a1"}},{"key":"agent.name","value":{"stringValue":"support"}},{"key":"tool.name","value":{"stringValue":"crm.search"}},{"key":"gen_ai.system","value":{"stringValue":"declared-provider"}}]}]}]}]}`
	events, skipped, err := ReadSource(strings.NewReader(input), SourceOTelJSON, Options{})
	if err != nil {
		t.Fatalf("ReadSource() error = %v", err)
	}
	if skipped != 0 || len(events) != 1 {
		t.Fatalf("unexpected events: skipped=%d events=%+v", skipped, events)
	}
	event := events[0]
	if event.AgentID != "a1" || event.Target != "crm.search" || event.Environment != "production" || !event.Success {
		t.Fatalf("unexpected normalized OTel event: %+v", event)
	}
}

func TestReadAPIGatewayJSONL(t *testing.T) {
	input := `{"timestamp":"2026-01-02T03:04:05Z","requestId":"req-1","agentId":"a1","agent_name":"support","environment":"production","operation":"http_request","target":"/customers","provider":"crm","action":"read","status_code":200}
{"timestamp":"2026-01-02T03:05:05Z","agent_id":"a1","operation":"http_request","target":"/customers","status":"error","success":true}`
	events, skipped, err := ReadSource(strings.NewReader(input), SourceAPIGateway, Options{})
	if err != nil {
		t.Fatalf("ReadSource() error = %v", err)
	}
	if skipped != 0 || len(events) != 2 {
		t.Fatalf("unexpected events: skipped=%d events=%+v", skipped, events)
	}
	if events[0].RequestID != "req-1" || events[0].AgentID != "a1" || events[1].Success {
		t.Fatalf("unexpected normalized gateway events: %+v", events)
	}
}

func TestReadSourceRejectsUnknownSource(t *testing.T) {
	if _, _, err := ReadSource(strings.NewReader("{}"), Source("unknown"), Options{}); err == nil {
		t.Fatal("ReadSource() accepted unknown source")
	}
}
