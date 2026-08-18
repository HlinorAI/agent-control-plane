package adversarial

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/HlinorAI/agent-control-plane/internal/scan"
)

type manifest struct {
	Cases []testCase `json:"cases"`
}

type testCase struct {
	ID                 string   `json:"id"`
	Description        string   `json:"description"`
	Root               string   `json:"root"`
	Expected           expected `json:"expected"`
	Secrets            []string `json:"secrets"`
	SecurityInvariants []string `json:"security_invariants"`
	Formats            []string `json:"formats"`
}

type expected struct {
	ExitCode   int            `json:"exit_code"`
	RuleCounts map[string]int `json:"rule_counts"`
	MinAgents  int            `json:"min_agents"`
	MinSources int            `json:"min_sources"`
}

func TestAdversarialCorpus(t *testing.T) {
	repositoryRoot := findRepositoryRoot(t)
	manifestPath := filepath.Join(repositoryRoot, "testdata", "adversarial", "manifest.yaml")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	var corpus manifest
	if err := json.Unmarshal(manifestBytes, &corpus); err != nil {
		t.Fatalf("decode %s as JSON-compatible YAML: %v", manifestPath, err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("adversarial manifest has no cases")
	}

	seen := map[string]bool{}
	for _, tc := range corpus.Cases {
		tc := tc
		t.Run(tc.ID, func(t *testing.T) {
			if seen[tc.ID] {
				t.Fatalf("duplicate case id %q", tc.ID)
			}
			seen[tc.ID] = true
			if tc.Description == "" || tc.Root == "" || len(tc.Formats) == 0 {
				t.Fatal("case requires description, root, and at least one format")
			}
			assertManifestInvariantCoverage(t, tc.SecurityInvariants)
			if err := validateSecretInvariant(tc.SecurityInvariants, tc.Secrets); err != nil {
				t.Fatal(err)
			}
			if tc.Expected.ExitCode != 0 {
				t.Fatalf("package-level harness only supports expected exit code 0, got %d", tc.Expected.ExitCode)
			}

			sourceRoot := filepath.Join(repositoryRoot, filepath.FromSlash(tc.Root))
			if info, err := os.Stat(sourceRoot); err != nil || !info.IsDir() {
				t.Fatalf("fixture root is not a directory: %s", sourceRoot)
			}
			fixtureRoot := filepath.Join(t.TempDir(), "fixture")
			if err := copyTree(sourceRoot, fixtureRoot); err != nil {
				t.Fatal(err)
			}

			formats := append([]string(nil), tc.Formats...)
			sort.Strings(formats)
			for _, format := range formats {
				format := format
				t.Run(format, func(t *testing.T) {
					first, err := runAndAssert(t, fixtureRoot, tc, format)
					if err != nil {
						t.Fatal(err)
					}
					if !containsInvariant(tc.SecurityInvariants, "deterministic") {
						return
					}
					for i := 0; i < 2; i++ {
						repeated, err := runAndAssert(t, fixtureRoot, tc, format)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(first, repeated) {
							t.Fatalf("non-deterministic %s output on repetition %d", format, i+2)
						}
					}
				})
			}
		})
	}
}

func runAndAssert(t *testing.T, root string, tc testCase, format string) ([]byte, error) {
	t.Helper()
	var before treeSnapshot
	var err error
	if containsInvariant(tc.SecurityInvariants, "no_filesystem_mutation") {
		before, err = snapshotTree(root)
		if err != nil {
			return nil, fmt.Errorf("snapshot fixture before scan: %w", err)
		}
	}
	report, err := scan.Run(root, scan.Options{})
	if err != nil {
		return nil, err
	}
	assertReportInvariants(t, report, tc.SecurityInvariants)
	if containsInvariant(tc.SecurityInvariants, "no_filesystem_mutation") {
		after, err := snapshotTree(root)
		if err != nil {
			return nil, fmt.Errorf("snapshot fixture after scan: %w", err)
		}
		assertTreeUnchanged(t, before, after)
	}
	if len(report.Agents) < tc.Expected.MinAgents {
		return nil, fmt.Errorf("case %s: expected at least %d agents, got %d", tc.ID, tc.Expected.MinAgents, len(report.Agents))
	}
	if len(report.Sources) < tc.Expected.MinSources {
		return nil, fmt.Errorf("case %s: expected at least %d sources, got %d", tc.ID, tc.Expected.MinSources, len(report.Sources))
	}
	counts := map[string]int{}
	for _, finding := range report.Findings {
		counts[finding.RuleID]++
	}
	for ruleID, minimum := range tc.Expected.RuleCounts {
		if counts[ruleID] < minimum {
			return nil, fmt.Errorf("case %s: expected at least %d findings for %s, got %d", tc.ID, minimum, ruleID, counts[ruleID])
		}
	}

	var output []byte
	switch format {
	case "json":
		output, err = json.MarshalIndent(report, "", "  ")
	case "sarif":
		output, err = report.SARIF()
	case "text":
		output = []byte(report.Text())
	default:
		return nil, fmt.Errorf("case %s: unsupported format %q", tc.ID, format)
	}
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", format, err)
	}
	if containsInvariant(tc.SecurityInvariants, "no_secret_leak") {
		for _, secret := range tc.Secrets {
			if bytes.Contains(output, []byte(secret)) {
				return nil, fmt.Errorf("case %s leaked synthetic secret in %s output", tc.ID, format)
			}
		}
	}
	if containsInvariant(tc.SecurityInvariants, "no_marker_created") {
		marker := filepath.Join(root, "SHOULD_NOT_EXIST")
		if _, err := os.Stat(marker); err == nil {
			return nil, fmt.Errorf("case %s executed inert marker command", tc.ID)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("check inert marker: %w", err)
		}
	}
	return output, nil
}

func containsInvariant(invariants []string, wanted string) bool {
	for _, invariant := range invariants {
		if invariant == wanted {
			return true
		}
	}
	return false
}

func findRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve harness location")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := destination
		if relative != "." {
			target = filepath.Join(destination, relative)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("fixture contains unsupported non-regular file %s", strings.TrimPrefix(path, source+string(filepath.Separator)))
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}
