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
	namePattern      = regexp.MustCompile(`(?im)^\s*["']?(agent[_ -]?(name|id)|name)["']?\s*[:=]`)
	identityPattern  = regexp.MustCompile(`(?im)^\s*["']?(identity|service[_ -]?account|principal|role)["']?\s*[:=]`)
	mcpPattern       = regexp.MustCompile(`(?im)^\s*["']?(mcp[_ -]?server|server[_ -]?name)["']?\s*[:=]`)
	listItemPattern  = regexp.MustCompile(`^\s*-\s*["']?([A-Za-z0-9._:/-]+)`)
	prodPattern      = regexp.MustCompile(`(?i)(production|prod|environment\s*[:=]\s*prod)`)
	runtimePattern   = regexp.MustCompile(`(?i)(^|/)(runtime|otel|traces?)(/|$)`)
	readOnlyPattern  = regexp.MustCompile(`(?i)(read[_ -]?only|readonly)`)
	writePattern     = regexp.MustCompile(`(?i)\b(delete|write|admin|update|create|send|execute)\b`)
	secretPattern    = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|private[_-]?key)\s*[:=]`)
)

type candidate struct {
	path            string
	line            int
	name            string
	kind            string
	models          []string
	tools           []string
	identity        string
	identityLine    int
	mcpServer       string
	mcpLine         int
	owner           string
	environment     string
	readOnly        bool
	writeScope      bool
	permissionLine  int
	approvedServers []string
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

	approvedServers := map[string]bool{}
	for _, item := range candidates {
		for _, server := range item.approvedServers {
			approvedServers[strings.ToLower(server)] = true
		}
	}

	sourceNames := map[string]bool{}
	for _, item := range candidates {
		if item.kind != "runtime" && item.kind != "registry" && item.name != "" {
			sourceNames[strings.ToLower(item.name)] = true
		}
	}

	identityAgents := map[string][]Agent{}
	agentItems := map[string]candidate{}
	for _, item := range candidates {
		if item.kind == "registry" {
			continue
		}
		if item.kind == "runtime" {
			if item.name != "" && !sourceNames[strings.ToLower(item.name)] {
				runtimeID := stableID("runtime-agent", item.name)
				report.Findings = append(report.Findings, Finding{
					ID:              stableID("finding", runtimeID+":ACP-002"),
					RuleID:          "ACP-002",
					Severity:        "High",
					Message:         "Runtime agent has no matching source inventory entry",
					AgentID:         runtimeID,
					Confidence:      0.75,
					Evidence:        []Evidence{{Path: item.path, Line: item.line}},
					RemediationHint: "Confirm the source repository and owner, or register this runtime agent explicitly.",
				})
			}
			continue
		}

		agentID := stableID("agent", item.path)
		agent := Agent{
			ID:          agentID,
			Name:        item.name,
			SourcePath:  item.path,
			Models:      item.models,
			Tools:       item.tools,
			Identity:    item.identity,
			MCPServer:   item.mcpServer,
			Environment: item.environment,
			Owner:       item.owner,
			Confidence:  0.60,
		}
		report.Agents = append(report.Agents, agent)
		agentItems[agentID] = item
		if item.identity != "" {
			identityAgents[strings.ToLower(item.identity)] = append(identityAgents[strings.ToLower(item.identity)], agent)
			if !containsIdentity(report.Identities, item.identity) {
				report.Identities = append(report.Identities, Identity{ID: stableID("identity", item.identity), Name: item.identity, SourcePath: item.path})
			}
		}
		if item.mcpServer != "" && !containsMCPServer(report.MCPServers, item.mcpServer) {
			report.MCPServers = append(report.MCPServers, MCPServer{ID: stableID("mcp", item.mcpServer), Name: item.mcpServer, Approved: approvedServers[strings.ToLower(item.mcpServer)], SourcePath: item.path})
		}
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
		if item.readOnly && item.writeScope {
			report.Findings = append(report.Findings, Finding{
				ID:              stableID("finding", agentID+":ACP-004"),
				RuleID:          "ACP-004",
				Severity:        "High",
				Message:         "Read-only use case references a write/admin capability",
				AgentID:         agentID,
				Confidence:      0.80,
				Evidence:        []Evidence{{Path: item.path, Line: item.permissionLine}},
				RemediationHint: "Remove the write scope or document an explicit approved exception.",
			})
		}
		if item.mcpServer != "" && !approvedServers[strings.ToLower(item.mcpServer)] {
			report.Findings = append(report.Findings, Finding{
				ID:              stableID("finding", agentID+":ACP-005"),
				RuleID:          "ACP-005",
				Severity:        "High",
				Message:         "MCP server is not present in the approved registry",
				AgentID:         agentID,
				Confidence:      0.85,
				Evidence:        []Evidence{{Path: item.path, Line: item.mcpLine}},
				RemediationHint: "Review the server provenance and add it to the approved registry only after ownership and permission review.",
			})
		}
	}

	for identity, agents := range identityAgents {
		if len(agents) < 2 {
			continue
		}
		for _, agent := range agents {
			item := agentItems[agent.ID]
			report.Findings = append(report.Findings, Finding{
				ID:              stableID("finding", agent.ID+":ACP-003"),
				RuleID:          "ACP-003",
				Severity:        "High",
				Message:         fmt.Sprintf("Identity %q is shared by unrelated agent sources", identity),
				AgentID:         agent.ID,
				Confidence:      0.70,
				Evidence:        []Evidence{{Path: item.path, Line: item.identityLine}},
				RemediationHint: "Use a dedicated least-privilege identity or document an approved shared-identity exception.",
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
	var owner, environment, name, identity, mcpServer string
	identityLine, mcpLine, permissionLine := 0, 0, 0
	readOnly, writeScope := false, false
	approvedServers := []string{}
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
		if name == "" && namePattern.MatchString(line) {
			name = declarationValue(line, namePattern)
		}
		if identity == "" && identityPattern.MatchString(line) {
			identity = declarationValue(line, identityPattern)
			identityLine = lineNumber
		}
		if mcpServer == "" && mcpPattern.MatchString(line) {
			mcpServer = declarationValue(line, mcpPattern)
			mcpLine = lineNumber
		}
		if readOnlyPattern.MatchString(line) {
			readOnly = true
		}
		if writePattern.MatchString(line) {
			writeScope = true
			permissionLine = lineNumber
		}
		if strings.Contains(strings.ToLower(relative), "approved") && strings.Contains(strings.ToLower(relative), "mcp") {
			if match := listItemPattern.FindStringSubmatch(line); len(match) == 2 {
				approvedServers = appendUnique(approvedServers, match[1])
			}
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
	if firstSignal == 0 && identity == "" && mcpServer == "" && len(approvedServers) == 0 && !runtimePattern.MatchString(relative) {
		return nil, nil
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(relative), filepath.Ext(relative))
	}
	kind := "source"
	if len(approvedServers) > 0 {
		kind = "registry"
	} else if runtimePattern.MatchString(relative) {
		kind = "runtime"
	}
	if firstSignal == 0 {
		firstSignal = 1
	}
	return &candidate{
		path: relative, line: firstSignal, name: name, kind: kind, models: models, tools: tools,
		identity: identity, identityLine: identityLine, mcpServer: mcpServer, mcpLine: mcpLine,
		owner: owner, environment: environment, readOnly: readOnly, writeScope: writeScope,
		permissionLine: permissionLine, approvedServers: approvedServers,
	}, nil
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

func containsIdentity(values []Identity, name string) bool {
	for _, value := range values {
		if strings.EqualFold(value.Name, name) {
			return true
		}
	}
	return false
}

func containsMCPServer(values []MCPServer, name string) bool {
	for _, value := range values {
		if strings.EqualFold(value.Name, name) {
			return true
		}
	}
	return false
}

func stableID(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + ":" + value))
	return fmt.Sprintf("%s_%x", kind, sum[:8])
}
