package scan

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxFiles      = 10_000
	maxFileBytes  = 1 << 20
	maxTotalBytes = 64 << 20
	maxLineBytes  = 256 << 10
)

var (
	modelPattern     = regexp.MustCompile(`(?i)(openai|anthropic|claude|gemini|vertexai|bedrock|ollama|litellm)`)
	toolPattern      = regexp.MustCompile(`(?i)(mcp|tool[_ -]?call|function[_ -]?call|tools\s*:)`)
	frameworkPattern = regexp.MustCompile(`(?i)(langgraph|langchain|crewai|autogen|pydantic[_ -]?ai)`)
	ownerPattern     = regexp.MustCompile(`(?im)^\s*(owner|team|maintainer)\s*[:=]`)
	prodPattern      = regexp.MustCompile(`(?i)(production|prod|environment\s*[:=]\s*prod)`)
	secretPattern    = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|private[_-]?key)\s*[:=]`)
)

type candidate struct {
	path        string
	line        int
	name        string
	models      []string
	tools       []string
	owner       string
	environment string
}

func Run(root string, options Options) (Report, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Report{}, fmt.Errorf("resolve scan root: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return Report{}, fmt.Errorf("stat scan root: %w", err)
	}
	if !info.IsDir() {
		return Report{}, errors.New("scan root must be a directory")
	}

	report := Report{
		SchemaVersion: schemaVersion,
		Root:          absRoot,
		ReadOnly:      true,
		MetadataOnly:  true,
	}
	var totalBytes int64
	var candidates []candidate

	err = filepath.WalkDir(absRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			report.FilesSkipped++
			return nil
		}
		if path == absRoot {
			return nil
		}
		if entry.IsDir() {
			if ignoredDirectory(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || !supportedFile(path, entry.Name()) {
			report.FilesSkipped++
			return nil
		}
		if report.FilesScanned >= maxFiles || totalBytes >= maxTotalBytes {
			report.FilesSkipped++
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil || fileInfo.Size() > maxFileBytes {
			report.FilesSkipped++
			return nil
		}
		rel, err := filepath.Rel(absRoot, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			report.FilesSkipped++
			return nil
		}
		report.FilesScanned++
		report.ReadFiles = append(report.ReadFiles, filepath.ToSlash(rel))
		totalBytes += fileInfo.Size()
		if options.DryRun {
			return nil
		}
		found, err := inspectFile(path, filepath.ToSlash(rel))
		if err != nil {
			report.FilesSkipped++
			return nil
		}
		if found != nil {
			candidates = append(candidates, *found)
		}
		return nil
	})
	if err != nil {
		return Report{}, fmt.Errorf("walk scan root: %w", err)
	}

	for _, item := range candidates {
		agentID := stableID("agent", item.path)
		agent := Agent{
			ID:          agentID,
			Name:        item.name,
			SourcePath:  item.path,
			Models:      item.models,
			Tools:       item.tools,
			Environment: item.environment,
			Owner:       item.owner,
			Confidence:  0.60,
		}
		report.Agents = append(report.Agents, agent)
		if item.owner == "" {
			severity := "Medium"
			if item.environment == "production" {
				severity = "High"
			}
			report.Findings = append(report.Findings, Finding{
				ID:              stableID("finding", agentID+":ACP-001"),
				RuleID:          "ACP-001",
				Severity:        severity,
				Message:         "Potential owner gap: no owner/team declaration found in the scanned source",
				AgentID:         agentID,
				Confidence:      0.55,
				Evidence:        []Evidence{{Path: item.path, Line: item.line}},
				RemediationHint: "Confirm an accountable owner or team and record the ownership source.",
			})
		}
	}
	sortReport(&report)
	return report, nil
}

func inspectFile(path, relative string) (*candidate, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxLineBytes)
	var lineNumber int
	var models, tools []string
	var owner, environment string
	firstSignal := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.Contains(line, "regexp.MustCompile") {
			// Do not let the scanner's own detection vocabulary become inventory.
			continue
		}
		if secretPattern.MatchString(line) {
			// Never copy or emit the line. The scanner only retains safe metadata.
			continue
		}
		if firstSignal == 0 && (frameworkPattern.MatchString(line) || modelPattern.MatchString(line) || toolPattern.MatchString(line)) {
			firstSignal = lineNumber
		}
		if modelPattern.MatchString(line) {
			models = appendUnique(models, modelLabel(line))
		}
		if toolPattern.MatchString(line) {
			tools = appendUnique(tools, toolLabel(line))
		}
		if owner == "" {
			owner = declarationValue(line, ownerPattern)
		}
		if environment == "" && prodPattern.MatchString(line) {
			environment = "production"
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if firstSignal == 0 {
		return nil, nil
	}
	name := strings.TrimSuffix(filepath.Base(relative), filepath.Ext(relative))
	return &candidate{path: relative, line: firstSignal, name: name, models: models, tools: tools, owner: owner, environment: environment}, nil
}

func supportedFile(path, name string) bool {
	if strings.EqualFold(name, "Dockerfile") || strings.EqualFold(name, "Makefile") {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".java", ".rs", ".yaml", ".yml", ".json", ".toml":
		return true
	default:
		return false
	}
}

func ignoredDirectory(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__":
		return true
	default:
		return false
	}
}

func declarationValue(line string, pattern *regexp.Regexp) string {
	if !pattern.MatchString(line) {
		return ""
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		parts = strings.SplitN(line, "=", 2)
	}
	if len(parts) != 2 {
		return "unknown"
	}
	value := strings.TrimSpace(strings.Trim(parts[1], "`\"'"))
	if value == "" || secretPattern.MatchString(value) {
		return "unknown"
	}
	return value
}

func modelLabel(line string) string {
	lower := strings.ToLower(line)
	for _, label := range []string{"openai", "anthropic", "claude", "gemini", "vertexai", "bedrock", "ollama", "litellm"} {
		if strings.Contains(lower, label) {
			return label
		}
	}
	return "model-provider-reference"
}

func toolLabel(line string) string {
	if strings.Contains(strings.ToLower(line), "mcp") {
		return "mcp-reference"
	}
	return "tool-reference"
}

func appendUnique(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

func stableID(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + ":" + value))
	return fmt.Sprintf("%s_%x", kind, sum[:8])
}
