package runtime

import (
	"strings"
	"testing"
	"time"
)

func TestAuditSARIFIsDeterministic(t *testing.T) {
	report := AuditReport{SchemaVersion: "runtime-audit.v1", Findings: []Finding{{ID: "runtime_1", RuleID: "ACP-R001", Severity: "High", Message: "undeclared target", AgentID: "a1", Confidence: 0.9, RemediationHint: "declare target"}}}
	first, err := report.SARIF()
	if err != nil {
		t.Fatalf("SARIF() error = %v", err)
	}
	second, err := report.SARIF()
	if err != nil {
		t.Fatalf("SARIF() error = %v", err)
	}
	if string(first) != string(second) || !strings.Contains(string(first), "ACP-R001") || !strings.Contains(string(first), "error") {
		t.Fatalf("unexpected SARIF output: %s", first)
	}
}

func TestRuntimeBaselineAndSuppression(t *testing.T) {
	report := AuditReport{SchemaVersion: "runtime-audit.v1", Findings: []Finding{{ID: "runtime_keep", RuleID: "ACP-R001", Severity: "High", Message: "keep"}, {ID: "runtime_old", RuleID: "ACP-R002", Severity: "High", Message: "old"}}}
	baseline := `{"schema_version":"runtime-audit.v1","findings":[{"id":"runtime_old"}]}`
	if err := ApplyBaseline(&report, strings.NewReader(baseline)); err != nil {
		t.Fatalf("ApplyBaseline() error = %v", err)
	}
	if len(report.Findings) != 1 || report.Findings[0].ID != "runtime_keep" {
		t.Fatalf("unexpected baseline result: %+v", report.Findings)
	}
	suppressions := `{"suppressions":[{"finding_id":"runtime_keep","reason":"accepted risk","expires_at":"2099-01-01T00:00:00Z"}]}`
	if err := ApplySuppressions(&report, strings.NewReader(suppressions), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("ApplySuppressions() error = %v", err)
	}
	if !report.Findings[0].Suppressed || report.Findings[0].SuppressionReason != "accepted risk" {
		t.Fatalf("unexpected suppression result: %+v", report.Findings[0])
	}
}

func TestReadEventsRejectsSensitiveMetadataKeys(t *testing.T) {
	input := `{"timestamp":"2026-01-02T03:04:05Z","agent_id":"a1","operation":"tool_call","target":"crm.search","success":true,"arguments":{"customer_id":"123"}}`
	if _, _, err := ReadEvents(strings.NewReader(input), Options{}); err == nil {
		t.Fatal("ReadEvents() accepted sensitive arguments field")
	}
}

func TestReadEventsRejectsOversizedMetadata(t *testing.T) {
	input := `{"timestamp":"2026-01-02T03:04:05Z","agent_id":"a1","operation":"tool_call","target":"crm.search","provider":"` + strings.Repeat("x", 257) + `","success":true}`
	if _, _, err := ReadEvents(strings.NewReader(input), Options{}); err == nil {
		t.Fatal("ReadEvents() accepted oversized provider")
	}
}
