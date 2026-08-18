package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/HlinorAI/agent-control-plane/internal/scan"
)

type manifest struct {
	SchemaVersion string  `json:"schema_version"`
	Cases         []bench `json:"cases"`
}

type bench struct {
	ID         string `json:"id"`
	Directory  string `json:"directory"`
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	MinAgents  int    `json:"min_agents"`
	MaxAgents  int    `json:"max_agents"`
}

type result struct {
	ID                 string   `json:"id"`
	Repository         string   `json:"repository"`
	Ref                string   `json:"ref"`
	Agents             int      `json:"agents"`
	Findings           int      `json:"findings"`
	SourceACP005       int      `json:"source_acp005"`
	CodeExpressionHits int      `json:"code_expression_hits,omitempty"`
	Pass               bool     `json:"pass"`
	Errors             []string `json:"errors,omitempty"`
}

var benchmarkDottedIdentifierPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+$`)
var benchmarkBracketExpressionPattern = regexp.MustCompile(`(?i)\b(required|schema)\s*\[`)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "agentctl-benchmark:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("agentctl-benchmark", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "", "directory containing the pinned benchmark repositories")
	manifestPath := fs.String("manifest", "testdata/benchmark/manifest.json", "benchmark manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *root == "" {
		return errors.New("root is required")
	}
	data, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var input manifest
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if input.SchemaVersion != "1" || len(input.Cases) == 0 {
		return errors.New("unsupported or empty benchmark manifest")
	}

	results := make([]result, 0, len(input.Cases))
	allPassed := true
	for _, item := range input.Cases {
		current := result{ID: item.ID, Repository: item.Repository, Ref: item.Ref}
		path := filepath.Join(*root, item.Directory)
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			current.Errors = append(current.Errors, "benchmark repository directory is missing")
			current.Pass = false
			allPassed = false
			results = append(results, current)
			continue
		}
		report, err := scan.Run(path, scan.Options{})
		if err != nil {
			current.Errors = append(current.Errors, err.Error())
			current.Pass = false
			allPassed = false
			results = append(results, current)
			continue
		}
		current.Agents = len(report.Agents)
		current.Findings = len(report.Findings)
		for _, finding := range report.Findings {
			if finding.RuleID == "ACP-005" && len(finding.Evidence) > 0 && !isMCPPolicyPath(finding.Evidence[0].Path) {
				current.SourceACP005++
			}
		}
		for _, agent := range report.Agents {
			if codeExpression(agent.Name) {
				current.CodeExpressionHits++
			}
			for _, model := range agent.Models {
				if codeExpression(model) {
					current.CodeExpressionHits++
				}
			}
		}
		if current.Agents < item.MinAgents {
			current.Errors = append(current.Errors, fmt.Sprintf("agent count %d is below minimum %d", current.Agents, item.MinAgents))
		}
		if item.MaxAgents > 0 && current.Agents > item.MaxAgents {
			current.Errors = append(current.Errors, fmt.Sprintf("agent count %d exceeds maximum %d", current.Agents, item.MaxAgents))
		}
		if current.SourceACP005 > 0 {
			current.Errors = append(current.Errors, "ACP-005 was emitted for a non-policy source")
		}
		if current.CodeExpressionHits > 0 {
			current.Errors = append(current.Errors, "code expressions were emitted as agent metadata")
		}
		current.Pass = len(current.Errors) == 0
		if !current.Pass {
			allPassed = false
		}
		results = append(results, current)
	}
	output := struct {
		SchemaVersion string   `json:"schema_version"`
		Passed        bool     `json:"passed"`
		Results       []result `json:"results"`
	}{SchemaVersion: "1", Passed: allPassed, Results: results}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("encode benchmark report: %w", err)
	}
	if !allPassed {
		return errors.New("benchmark thresholds failed")
	}
	return nil
}

func isMCPPolicyPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == ".mcp.json" || base == "server.json" {
		return true
	}
	extension := strings.ToLower(filepath.Ext(base))
	return (extension == ".json" || extension == ".yaml" || extension == ".yml") && (strings.Contains(base, "mcp") || strings.Contains(base, "server") || strings.Contains(base, "manifest"))
}

func codeExpression(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"(", ")", "[", "]", "|", "select_choice", "removeprefix"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if benchmarkBracketExpressionPattern.MatchString(value) || benchmarkDottedIdentifierPattern.MatchString(lower) {
		return true
	}
	switch lower {
	case "str", "model", "name", "bool", "int", "model_name":
		return true
	default:
		return false
	}
}
