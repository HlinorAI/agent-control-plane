package adversarial

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/HlinorAI/agent-control-plane/internal/scan"
)

var knownSecurityInvariants = map[string]bool{
	"deterministic":          true,
	"no_marker_created":      true,
	"no_secret_leak":         true,
	"no_filesystem_mutation": true,
	"safe_evidence":          true,
	"severity_integrity":     true,
}

func validateSecurityInvariants(t *testing.T, invariants []string) {
	t.Helper()
	for _, invariant := range invariants {
		if !knownSecurityInvariants[invariant] {
			t.Fatalf("unknown security invariant %q", invariant)
		}
	}
}

func validateSecretInvariant(invariants, secrets []string) error {
	declared := containsInvariant(invariants, "no_secret_leak")
	if declared && len(secrets) == 0 {
		return fmt.Errorf("no_secret_leak requires at least one secret value")
	}
	if !declared && len(secrets) > 0 {
		return fmt.Errorf("manifest secrets require the no_secret_leak invariant")
	}
	return nil
}

func assertReportInvariants(t *testing.T, report scan.Report, invariants []string) {
	t.Helper()
	if !report.ReadOnly || !report.MetadataOnly {
		t.Fatalf("report lost read-only metadata contract: read_only=%t metadata_only=%t", report.ReadOnly, report.MetadataOnly)
	}
	if containsInvariant(invariants, "safe_evidence") {
		for _, readFile := range report.ReadFiles {
			assertRelativePath(t, "read file", readFile)
		}
		for _, source := range report.Sources {
			assertRelativePath(t, "source", source.Path)
		}
		for _, agent := range report.Agents {
			assertRelativePath(t, "agent", agent.SourcePath)
		}
		for _, model := range report.Models {
			assertRelativePath(t, "model", model.SourcePath)
		}
		for _, identity := range report.Identities {
			assertRelativePath(t, "identity", identity.SourcePath)
		}
		for _, server := range report.MCPServers {
			assertRelativePath(t, "MCP server", server.SourcePath)
		}
		for _, relationship := range report.Relationships {
			assertRelativePath(t, "relationship evidence", relationship.Evidence.Path)
			if relationship.Evidence.Line < 1 {
				t.Fatalf("relationship %s has invalid evidence line %d", relationship.ID, relationship.Evidence.Line)
			}
		}
		for _, finding := range report.Findings {
			for _, evidence := range finding.Evidence {
				assertRelativePath(t, "finding evidence", evidence.Path)
				if evidence.Line < 1 {
					t.Fatalf("finding %s has invalid evidence line %d", finding.ID, evidence.Line)
				}
			}
		}
	}
	if containsInvariant(invariants, "severity_integrity") {
		for _, agent := range report.Agents {
			assertConfidence(t, "agent "+agent.ID, agent.Confidence)
		}
		for _, relationship := range report.Relationships {
			assertConfidence(t, "relationship "+relationship.ID, relationship.Confidence)
		}
		for _, finding := range report.Findings {
			if !knownSeverity(finding.Severity) {
				t.Fatalf("finding %s has invalid severity %q", finding.ID, finding.Severity)
			}
			assertConfidence(t, "finding "+finding.ID, finding.Confidence)
		}
	}
}

func assertRelativePath(t *testing.T, kind, value string) {
	t.Helper()
	if err := validateRelativePath(value); err != nil {
		t.Fatalf("%s path is not safe: %q: %v", kind, value, err)
	}
}

func assertConfidence(t *testing.T, kind string, value float64) {
	t.Helper()
	if err := validateConfidence(value); err != nil {
		t.Fatalf("%s confidence is outside [0,1]: %v: %v", kind, value, err)
	}
}

func validateRelativePath(value string) error {
	clean := path.Clean(filepath.ToSlash(value))
	if value == "" {
		return fmt.Errorf("path is empty")
	}
	if path.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("path escapes the scan root")
	}
	return nil
}

func validateConfidence(value float64) error {
	if value < 0 || value > 1 {
		return fmt.Errorf("value must be between 0 and 1")
	}
	return nil
}

func knownSeverity(value string) bool {
	switch value {
	case "Critical", "High", "Medium", "Note":
		return true
	default:
		return false
	}
}

type treeSnapshot map[string]string

func snapshotTree(root string) (treeSnapshot, error) {
	snapshot := treeSnapshot{}
	err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported fixture entry %s", filePath)
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		relative, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		snapshot[filepath.ToSlash(relative)] = fmt.Sprintf("%o:%d:%x", info.Mode().Perm(), info.Size(), digest)
		return nil
	})
	return snapshot, err
}

func assertTreeUnchanged(t *testing.T, before, after treeSnapshot) {
	t.Helper()
	if err := compareSnapshots(before, after); err != nil {
		t.Fatal(err)
	}
}

func compareSnapshots(before, after treeSnapshot) error {
	if len(before) != len(after) {
		return fmt.Errorf("scanner mutated fixture file set: before=%d after=%d", len(before), len(after))
	}
	keys := make([]string, 0, len(before))
	for key := range before {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if before[key] != after[key] {
			return fmt.Errorf("scanner mutated fixture file %s: before=%s after=%s", key, before[key], after[key])
		}
	}
	return nil
}

func assertManifestInvariantCoverage(t *testing.T, invariants []string) {
	t.Helper()
	validateSecurityInvariants(t, invariants)
	for _, wanted := range []string{"deterministic", "no_filesystem_mutation", "safe_evidence", "severity_integrity"} {
		if !containsInvariant(invariants, wanted) {
			t.Fatalf("manifest case does not declare required invariant %q", wanted)
		}
	}
}

func TestInvariantHelpersRejectUnsafeValues(t *testing.T) {
	for _, value := range []string{"", "/tmp/secret", "../outside", "a/../../outside"} {
		if err := validateRelativePath(value); err == nil {
			t.Errorf("validateRelativePath(%q) accepted unsafe path", value)
		}
	}
	for _, value := range []float64{-0.01, 1.01} {
		if err := validateConfidence(value); err == nil {
			t.Errorf("validateConfidence(%v) accepted out-of-range value", value)
		}
	}
	for _, value := range []string{"Critical", "High", "Medium", "Note"} {
		if !knownSeverity(value) {
			t.Errorf("knownSeverity(%q) rejected supported value", value)
		}
	}
	if knownSeverity("") || knownSeverity("Low") {
		t.Fatal("knownSeverity accepted unsupported severity")
	}
	if err := compareSnapshots(treeSnapshot{"a": "one"}, treeSnapshot{"a": "two"}); err == nil {
		t.Fatal("compareSnapshots accepted changed file content")
	}
	if err := validateSecretInvariant([]string{"no_secret_leak"}, nil); err == nil {
		t.Fatal("validateSecretInvariant accepted a secret invariant without secrets")
	}
	if err := validateSecretInvariant(nil, []string{"synthetic-secret"}); err == nil {
		t.Fatal("validateSecretInvariant accepted undeclared secrets")
	}
}
