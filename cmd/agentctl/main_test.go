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
