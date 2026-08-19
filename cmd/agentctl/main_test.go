package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HlinorAI/agent-control-plane/internal/scan"
)

func TestRunUsesProvidedScanPath(t *testing.T) {
	var output bytes.Buffer
	var errors bytes.Buffer
	if err := run([]string{"scan", "../../testdata/demo", "--format", "json"}, &output, &errors); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"root":`) || !strings.Contains(output.String(), "crm-agent") {
		t.Fatalf("provided path was not scanned: %s", output.String())
	}
	if strings.Contains(output.String(), "PROJECT_PLAN.md") {
		t.Fatalf("scanner ignored provided path and scanned project root: %s", output.String())
	}
}

func TestRunVersion(t *testing.T) {
	var output bytes.Buffer
	var errors bytes.Buffer
	if err := run([]string{"version"}, &output, &errors); err != nil {
		t.Fatal(err)
	}
	if output.String() != "agentctl dev\n" {
		t.Fatalf("unexpected version output: %q", output.String())
	}
}

func TestRunHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"scan", "--help"}, {"init", "--help"}} {
		var output bytes.Buffer
		var errors bytes.Buffer
		if err := run(args, &output, &errors); err != nil {
			t.Fatalf("help failed for %v: %v", args, err)
		}
		if !strings.Contains(output.String(), "agentctl - read-only AI agent inventory and risk scanner") || !strings.Contains(output.String(), "--baseline") {
			t.Fatalf("incomplete help for %v: %s", args, output.String())
		}
	}
}

func TestRunSARIFOutput(t *testing.T) {
	var output bytes.Buffer
	var errors bytes.Buffer
	if err := run([]string{"scan", "../../testdata/demo", "--format", "sarif"}, &output, &errors); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"\"version\": \"2.1.0\"", "\"ruleId\": \"ACP-006\"", "\"startLine\": 5"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("SARIF output missing %q: %s", expected, output.String())
		}
	}
}

func TestRunFailOnSeverity(t *testing.T) {
	var output bytes.Buffer
	var errors bytes.Buffer
	if err := run([]string{"scan", "../../testdata/demo", "--format", "json", "--fail-on", "critical"}, &output, &errors); err == nil || !strings.Contains(err.Error(), "critical severity") {
		t.Fatalf("expected critical threshold failure, got %v", err)
	}
	if !strings.Contains(output.String(), `"findings"`) {
		t.Fatalf("expected report output before threshold failure: %s", output.String())
	}
}

func TestRunBaselineSuppressesKnownFindings(t *testing.T) {
	root := "../../testdata/demo"
	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	var baseline bytes.Buffer
	var errors bytes.Buffer
	if err := run([]string{"scan", root, "--format", "json"}, &baseline, &errors); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, baseline.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"scan", root, "--format", "json", "--baseline", baselinePath}, &output, &errors); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"findings": []`) {
		t.Fatalf("baseline did not suppress known findings: %s", output.String())
	}
}

func TestRunSuppressionsRequireReasonAndExpiry(t *testing.T) {
	root := t.TempDir()
	agentPath := filepath.Join(root, "agents", "demo_agent.py")
	if err := os.MkdirAll(filepath.Dir(agentPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentPath, []byte("name: demo-agent\nmodel: openai/gpt-4o\nenvironment: production\ndisable_path: runbook/disable-agent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var reportOutput bytes.Buffer
	var errors bytes.Buffer
	if err := run([]string{"scan", root, "--format", "json"}, &reportOutput, &errors); err != nil {
		t.Fatal(err)
	}
	var report scan.Report
	if err := json.Unmarshal(reportOutput.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("demo report has no finding to suppress")
	}
	selectedID := ""
	for _, finding := range report.Findings {
		if finding.Severity == "High" {
			selectedID = finding.ID
			break
		}
	}
	if selectedID == "" {
		t.Fatal("demo report has no high finding to suppress")
	}
	suppressionPath := filepath.Join(root, "agents", "agents-suppressions.json")
	if err := os.MkdirAll(filepath.Dir(suppressionPath), 0o700); err != nil {
		t.Fatal(err)
	}
	payload := `{"suppressions":[{"finding_id":"` + selectedID + `","reason":"accepted until remediation","expires_at":"2099-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(suppressionPath, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"scan", root, "--format", "json", "--suppressions", suppressionPath}, &output, &errors); err != nil {
		t.Fatal(err)
	}
	var suppressed scan.Report
	if err := json.Unmarshal(output.Bytes(), &suppressed); err != nil {
		t.Fatal(err)
	}
	if len(suppressed.Findings) != len(report.Findings) {
		t.Fatalf("suppressed findings must remain visible, before=%d after=%d", len(report.Findings), len(suppressed.Findings))
	}
	for _, path := range suppressed.ReadFiles {
		if path == "agents/agents-suppressions.json" {
			t.Fatalf("suppression file must stay out of discovery read_files: %+v", suppressed.ReadFiles)
		}
	}
	var suppressedFinding *scan.Finding
	for index := range suppressed.Findings {
		if suppressed.Findings[index].ID == selectedID {
			suppressedFinding = &suppressed.Findings[index]
			break
		}
	}
	if suppressedFinding == nil || !suppressedFinding.Suppressed || suppressedFinding.SuppressionReason != "accepted until remediation" || suppressedFinding.SuppressionExpiresAt != "2099-01-01T00:00:00Z" {
		t.Fatalf("suppression metadata was not preserved: %+v", suppressedFinding)
	}
	var sarifOutput bytes.Buffer
	if err := run([]string{"scan", root, "--format", "sarif", "--suppressions", suppressionPath, "--fail-on", "high"}, &sarifOutput, &errors); err != nil {
		t.Fatalf("suppressed high finding should not fail threshold: %v", err)
	}
	if !strings.Contains(sarifOutput.String(), `"suppressions"`) || !strings.Contains(sarifOutput.String(), `"kind": "external"`) || !strings.Contains(sarifOutput.String(), "accepted until remediation") {
		t.Fatalf("SARIF did not preserve suppression metadata: %s", sarifOutput.String())
	}
	var textOutput bytes.Buffer
	if err := run([]string{"scan", root, "--format", "text", "--suppressions", suppressionPath}, &textOutput, &errors); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(textOutput.String(), "(suppressed)") || !strings.Contains(textOutput.String(), "accepted until remediation") {
		t.Fatalf("text output did not preserve suppression metadata: %s", textOutput.String())
	}
}

func TestRunRejectsInvalidSuppression(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "suppressions.json")
	if err := os.WriteFile(path, []byte(`{"suppressions":[{"finding_id":"finding-1","reason":"","expires_at":"2099-01-01T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var errors bytes.Buffer
	err := run([]string{"scan", root, "--suppressions", path}, &output, &errors)
	if err == nil || !strings.Contains(err.Error(), "has no reason") {
		t.Fatalf("expected suppression validation error, got %v", err)
	}
}

func TestRunRejectsSuppressionOutsideScanRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "suppressions.json")
	if err := os.WriteFile(path, []byte(`{"suppressions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var errors bytes.Buffer
	err := run([]string{"scan", root, "--suppressions", path}, &output, &errors)
	if err == nil || !strings.Contains(err.Error(), "must stay inside the scan root") {
		t.Fatalf("expected suppression boundary error, got %v", err)
	}
}

func TestRunRejectsExpiredSuppression(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "suppressions.json")
	if err := os.WriteFile(path, []byte(`{"suppressions":[{"finding_id":"finding-1","reason":"temporary exception","expires_at":"2020-01-01T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var errors bytes.Buffer
	err := run([]string{"scan", root, "--suppressions", path}, &output, &errors)
	if err == nil || !strings.Contains(err.Error(), "is expired") {
		t.Fatalf("expected expired suppression error, got %v", err)
	}
}

func TestRunRejectsUnknownSuppressionFieldsAndFindingIDs(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{name: "unknown field", payload: `{"suppressions":[{"finding_id":"finding-1","reason":"temporary exception","expires_at":"2099-01-01T00:00:00Z","approved_by":"security"}]}`, want: "unknown field"},
		{name: "unknown finding", payload: `{"suppressions":[{"finding_id":"finding-1","reason":"temporary exception","expires_at":"2099-01-01T00:00:00Z"}]}`, want: "does not match a finding"},
		{name: "misspelled top level", payload: `{"supressions":[]}`, want: "unknown field"},
		{name: "empty list", payload: "{\"suppressions\":[]}", want: "at least one suppression"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "suppressions.json")
			if err := os.WriteFile(path, []byte(test.payload), 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			var errors bytes.Buffer
			err := run([]string{"scan", root, "--suppressions", path}, &output, &errors)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
}

func TestRunDebugWritesSafeDecisionsToStderr(t *testing.T) {
	var output bytes.Buffer
	var errors bytes.Buffer
	if err := run([]string{"scan", "../../testdata/demo", "--format", "json", "--debug"}, &output, &errors); err != nil {
		t.Fatal(err)
	}
	var report scan.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("debug output corrupted JSON: %v", err)
	}
	if !strings.Contains(errors.String(), "decision=") || strings.Contains(errors.String(), "prod-api-token") {
		t.Fatalf("debug output is missing a decision or contains sensitive material: %s", errors.String())
	}
}

func TestRunOutputAllowsExplicitPathAndUsesPrivateMode(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "report.json")
	var output bytes.Buffer
	var errors bytes.Buffer
	if err := run([]string{"scan", "../../testdata/demo", "--format", "json", "--output", outputPath}, &output, &errors); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"schema_version"`) {
		t.Fatalf("output file does not contain a report: %s", content)
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode is not private: %o", info.Mode().Perm())
	}
}

func TestRunRejectsSymlinkOutput(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	link := filepath.Join(directory, "report.json")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var output bytes.Buffer
	var errors bytes.Buffer
	err := run([]string{"scan", "../../testdata/demo", "--format", "json", "--output", link}, &output, &errors)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "keep" {
		t.Fatalf("symlink target was modified: %q", content)
	}
}

func TestRunRejectsMissingOutputDirectory(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "missing", "report.json")
	var output bytes.Buffer
	var errors bytes.Buffer
	err := run([]string{"scan", "../../testdata/demo", "--output", outputPath}, &output, &errors)
	if err == nil || !strings.Contains(err.Error(), "resolve output directory") {
		t.Fatalf("expected missing directory rejection, got %v", err)
	}
}

func TestRunRejectsInvalidBaseline(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "baseline.json")
	if err := os.WriteFile(path, []byte(`{"findings": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var errors bytes.Buffer
	err := run([]string{"scan", root, "--baseline", path}, &output, &errors)
	if err == nil || !strings.Contains(err.Error(), "not an agentctl JSON report") {
		t.Fatalf("expected invalid baseline error, got %v", err)
	}
}

func TestRunInitCreatesConfigWithoutOverwriting(t *testing.T) {
	root := t.TempDir()
	var output bytes.Buffer
	var errors bytes.Buffer
	if err := run([]string{"init", root}, &output, &errors); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".agentctl", "config.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "freshness_days: 30") || !strings.Contains(output.String(), path) {
		t.Fatalf("init did not create the expected config: output=%s config=%s", output.String(), content)
	}
	if err := run([]string{"init", root}, &output, &errors); err == nil {
		t.Fatal("init overwrote an existing config")
	}
}

func TestRunRejectsConfigOutsideScanRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(outside, []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var errors bytes.Buffer
	err := run([]string{"scan", root, "--config", outside}, &output, &errors)
	if err == nil || !strings.Contains(err.Error(), "config must stay inside the scan root") {
		t.Fatalf("expected config boundary error, got %v", err)
	}
}
