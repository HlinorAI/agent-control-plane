package policy

import (
	"testing"
	"time"

	"github.com/HlinorAI/agent-control-plane/internal/cloudaudit"
	"github.com/HlinorAI/agent-control-plane/internal/runtime"
)

func TestFromRuntimeCreatesReviewableDraft(t *testing.T) {
	draft := FromRuntime(runtime.AgentSummary{AgentID: "a1", Targets: []string{"crm.search"}, Environments: []string{"production"}, Operations: map[string]int{"tool_call": 3}}, []cloudaudit.Event{{AgentID: "a1", Timestamp: time.Now(), Action: "GetItem", Resource: "arn:aws:dynamodb:table/customers"}})
	if draft.SchemaVersion != "policy-draft.v1" || !draft.ReviewRequired || draft.Environment != "production" {
		t.Fatalf("unexpected draft: %+v", draft)
	}
	if len(draft.CloudResources) != 1 || draft.CloudResources[0] == "" {
		t.Fatalf("cloud resource missing: %+v", draft)
	}
}
