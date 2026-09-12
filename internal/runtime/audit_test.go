package runtime

import (
	"testing"
	"time"

	"github.com/HlinorAI/agent-control-plane/internal/scan"
)

func TestAuditFindsUndeclaredProductionWrite(t *testing.T) {
	runtimeReport := Aggregate([]Event{{
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), AgentID: "a1", AgentName: "support", Environment: "production", Operation: "tool_call", Target: "crm.write", Provider: "unlisted", Action: "write", Success: true,
	}}, 0)
	result := Audit(runtimeReport, scan.Report{
		Agents: []scan.Agent{{ID: "a1", Name: "support", Tools: []string{"crm.search"}, Models: []string{"m1"}}},
		Models: []scan.Model{{ID: "m1", Name: "declared-model", Provider: "declared-provider"}},
	})
	if result.MatchedAgents != 1 || len(result.Findings) != 3 {
		t.Fatalf("unexpected audit result: %+v", result)
	}
	seen := map[string]bool{}
	for _, finding := range result.Findings {
		seen[finding.RuleID] = true
	}
	for _, rule := range []string{"ACP-R001", "ACP-R002", "ACP-R003"} {
		if !seen[rule] {
			t.Fatalf("missing finding %s: %+v", rule, result.Findings)
		}
	}
}

func TestAuditRejectsAmbiguousNameMatch(t *testing.T) {
	runtimeReport := Aggregate([]Event{{
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), AgentName: "support", Operation: "tool_call", Target: "crm.search", Success: true,
	}}, 0)
	result := Audit(runtimeReport, scan.Report{Agents: []scan.Agent{{ID: "a1", Name: "support"}, {ID: "a2", Name: "support"}}})
	if result.MatchedAgents != 0 || result.Unmatched != 1 || len(result.Findings) != 1 || result.Findings[0].RuleID != "ACP-R004" {
		t.Fatalf("unexpected ambiguous match result: %+v", result)
	}
}
