package main

import (
	"bytes"
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
