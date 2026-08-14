package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDetectsAgentAndOwnerGapWithoutEmittingSecret(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "agents", "crm_agent.py")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	content := `# production agent
model = "openai"
MCP_TOOL = "crm.search"
API_KEY = "super-secret-value"
`
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.ReadOnly || !report.MetadataOnly {
		t.Fatalf("expected read-only metadata-only report: %+v", report)
	}
	if len(report.Agents) != 1 || len(report.Findings) != 1 {
		t.Fatalf("expected one agent and one finding, got %d and %d", len(report.Agents), len(report.Findings))
	}
	if report.Findings[0].RuleID != "ACP-001" || report.Findings[0].Severity != "High" {
		t.Fatalf("unexpected finding: %+v", report.Findings[0])
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "super-secret-value") || strings.Contains(string(encoded), "API_KEY") {
		t.Fatalf("report leaked secret material: %s", encoded)
	}
}

func TestRunDryRunDoesNotParseContent(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "agent.ts")
	if err := os.WriteFile(file, []byte("agent = openai(); MCP_TOOL = true"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 || len(report.Agents) != 0 || len(report.Findings) != 0 {
		t.Fatalf("dry-run parsed content: %+v", report)
	}
	if len(report.ReadFiles) != 1 || report.ReadFiles[0] != "agent.ts" {
		t.Fatalf("unexpected dry-run files: %+v", report.ReadFiles)
	}
}

func TestRunIgnoresDocumentationFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("production agent uses MCP and OpenAI"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 0 || len(report.Agents) != 0 || len(report.Findings) != 0 {
		t.Fatalf("documentation should not be inventoried: %+v", report)
	}
}

func TestRunDemoFixtureFindsRiskRulesAndCanonicalRelationships(t *testing.T) {
	report, err := Run(filepath.Join("..", "..", "testdata", "demo"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"ACP-001": false, "ACP-002": false, "ACP-003": false, "ACP-004": false, "ACP-005": false,
		"ACP-006": false, "ACP-007": false, "ACP-008": false, "ACP-009": false, "ACP-010": false,
	}
	for _, finding := range report.Findings {
		if _, ok := wanted[finding.RuleID]; ok {
			wanted[finding.RuleID] = true
		}
	}
	for ruleID, found := range wanted {
		if !found {
			t.Fatalf("demo fixture did not produce %s; findings=%+v", ruleID, report.Findings)
		}
	}
	if len(report.Agents) != 3 || len(report.Sources) != 6 || len(report.Models) != 3 {
		t.Fatalf("unexpected canonical inventory sizes: agents=%d sources=%d models=%d", len(report.Agents), len(report.Sources), len(report.Models))
	}
	if len(report.Identities) != 2 || report.Identities[0].Name != "shared-crm-role" && report.Identities[1].Name != "shared-crm-role" {
		t.Fatalf("expected shared identity inventory, got %+v", report.Identities)
	}
	edges := map[string]bool{}
	for _, relationship := range report.Relationships {
		edges[relationship.EdgeType] = true
	}
	for _, edge := range []string{"DISCOVERED_FROM", "USES_MODEL", "AUTHENTICATES_AS", "CONNECTS_TO"} {
		if !edges[edge] {
			t.Fatalf("missing canonical relationship %s: %+v", edge, report.Relationships)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "prod-api-token") {
		t.Fatalf("report leaked production credential material: %s", encoded)
	}
}

func TestRunProducesStableReport(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "demo")
	first, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("same inputs produced different reports\nfirst: %s\nsecond: %s", firstJSON, secondJSON)
	}
}
