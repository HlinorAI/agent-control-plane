package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteDefaultAndLoad(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, FileName)
	original := Default(".")
	if err := WriteDefault(path, original); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != "1" || loaded.FreshnessDays != 30 || loaded.WorkspaceRoot != "." {
		t.Fatalf("unexpected config scalars: %+v", loaded)
	}
	if len(loaded.Exclude) == 0 || loaded.Exclude[0] != ".agentctl" {
		t.Fatalf("unexpected exclusions: %+v", loaded.Exclude)
	}
	if err := WriteDefault(path, original); err == nil {
		t.Fatal("expected existing config to be preserved")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "secret") {
		t.Fatalf("default config contains secret-like material: %s", content)
	}
}
