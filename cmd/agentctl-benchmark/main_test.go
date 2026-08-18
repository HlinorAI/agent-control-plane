package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunBenchmarkPassesPinnedFixture(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "fixture")
	if err := os.MkdirAll(filepath.Join(repo, "agents"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "agents", "demo_agent.py"), []byte("name: demo-agent\nmodel: openai\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	manifest := `{"schema_version":"1","cases":[{"id":"fixture","directory":"fixture","repository":"local","ref":"test","min_agents":1,"max_agents":1}]}`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"--root", root, "--manifest", manifestPath}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Passed bool `json:"passed"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("benchmark did not pass: %s", output.String())
	}
}

func TestRunBenchmarkRejectsMissingRepository(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	manifest := `{"schema_version":"1","cases":[{"id":"missing","directory":"missing","repository":"local","ref":"test","min_agents":1,"max_agents":1}]}`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"--root", t.TempDir(), "--manifest", manifestPath}, &output, &bytes.Buffer{}); err == nil {
		t.Fatal("expected missing repository failure")
	}
	if !bytes.Contains(output.Bytes(), []byte(`"passed": false`)) {
		t.Fatalf("benchmark report did not record failure: %s", output.String())
	}
}

func TestCodeExpressionClassification(t *testing.T) {
	for _, value := range []string{"self.model", "args.model", "str", "model_name", "Required[str]", "schema[\"name\"]"} {
		if !codeExpression(value) {
			t.Errorf("expected code expression: %q", value)
		}
	}
	for _, value := range []string{"schema-sync-agent", "openai/gpt-4o", "claude-3-5-sonnet"} {
		if codeExpression(value) {
			t.Errorf("expected metadata value: %q", value)
		}
	}
}
