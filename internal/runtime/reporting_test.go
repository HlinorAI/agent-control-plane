package runtime

import (
	"strings"
	"testing"
)

func TestDiffReportsIsDeterministic(t *testing.T) {
	before := AuditReport{SchemaVersion: "runtime-audit.v1", Findings: []Finding{{ID: "old", RuleID: "ACP-R001", Severity: "High", Message: "old"}, {ID: "same", RuleID: "ACP-R002", Severity: "Medium", Message: "same"}}}
	after := AuditReport{SchemaVersion: "runtime-audit.v1", Findings: []Finding{{ID: "new", RuleID: "ACP-R003", Severity: "Critical", Message: "new"}, {ID: "same", RuleID: "ACP-R002", Severity: "Medium", Message: "same"}}}
	diff := DiffReports(before, after)
	if len(diff.Added) != 1 || diff.Added[0].ID != "new" || len(diff.Removed) != 1 || diff.Removed[0].ID != "old" || diff.Unchanged != 1 {
		t.Fatalf("unexpected diff: %+v", diff)
	}
	csv, err := diff.CSV()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csv), "added,new") || !strings.Contains(string(csv), "removed,old") {
		t.Fatalf("unexpected csv: %s", csv)
	}
	html, err := diff.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Runtime audit diff") {
		t.Fatalf("unexpected html: %s", html)
	}
}
