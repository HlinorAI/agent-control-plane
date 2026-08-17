package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
