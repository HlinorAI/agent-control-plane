package scan

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/HlinorAI/agent-control-plane/internal/config"
)

const (
	maxFiles      = 10_000
	maxFileBytes  = 1 << 20
	maxTotalBytes = 64 << 20
	maxLineBytes  = 256 << 10
)

var (
	modelPattern                = regexp.MustCompile(`(?i)\b(openai|anthropic|claude|gemini|vertexai|bedrock|ollama|litellm)\b\s*(?:[./:@_-]|\()`)
	modelDeclaration            = regexp.MustCompile(`(?im)^\s*["']?(model|model[_ -]+provider|provider)["']?\s*[:=]`)
	toolPattern                 = regexp.MustCompile(`(?im)^\s*["']?(mcp([_ -]+(server|tool))?|tools?|tool[_ -]+(call|name|definition)|function[_ -]+(call|name|definition))["']?\s*[:=]`)
	frameworkPattern            = regexp.MustCompile(`(?i)(langgraph|langchain|crewai|autogen|pydantic[_ -]?ai)`)
	ownerPattern                = regexp.MustCompile(`(?im)^\s*(owner|team|maintainer)\s*[:=]`)
	namePattern                 = regexp.MustCompile(`(?im)^\s*["']?(agent[_ -]?(name|id)|name)["']?\s*[:=]`)
	identityPattern             = regexp.MustCompile(`(?im)^\s*["']?(identity|service[_ -]?account|principal)["']?\s*[:=]`)
	mcpPattern                  = regexp.MustCompile(`(?im)^\s*["']?(mcp[_ -]+server|server[_ -]+name)["']?\s*[:=]`)
	listItemPattern             = regexp.MustCompile(`^\s*-\s*["']?([A-Za-z0-9._:/-]+)`)
	environmentPattern          = regexp.MustCompile(`(?im)^\s*["']?(environment|env)["']?\s*[:=]\s*["']?(production|prod|development|dev)["']?\s*$`)
	productionComment           = regexp.MustCompile(`(?i)\bproduction\s+agent\b`)
	runtimePattern              = regexp.MustCompile(`(?i)(^|/)(runtime|otel|traces?)(/|$)`)
	readOnlyPattern             = regexp.MustCompile(`(?i)(read[_ -]?only|readonly)`)
	writePattern                = regexp.MustCompile(`(?i)\b(delete|write|admin|update|create|send|execute)\b`)
	permissionDeclaration       = regexp.MustCompile(`(?im)^\s*["']?(tool|tools|scope|scopes|permission|permissions|capability|capabilities|operation|operations|access)["']?\s*[:=]`)
	secretPattern               = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|private[_-]?key)\s*[:=]`)
	productionCredentialPattern = regexp.MustCompile(`(?i)\b(production|prod)[_-]?(credential|token|key|secret)\b|\b(credential|token|key|secret)[_-]?(production|prod)\b`)
	sensitiveToolPattern        = regexp.MustCompile(`(?im)^\s*["']?sensitive[_ -]?tool["']?\s*[:=]`)
	approvalPattern             = regexp.MustCompile(`(?i)\b(approval|approved|exception|change[_ -]?ticket)\b\s*[:=]`)
	disablePathPattern          = regexp.MustCompile(`(?i)\b(disable|rollback|kill[_ -]?switch|shutdown|revoke)\b`)
	verifiedPattern             = regexp.MustCompile(`(?im)^\s*["']?(last[_ -]?verified|verified[_ -]?at)["']?\s*[:=]`)
	transportPattern            = regexp.MustCompile(`(?im)^\s*["']?transport["']?\s*[:=]`)
	authMethodPattern           = regexp.MustCompile(`(?im)^\s*["']?(auth[_ -]?method|authentication)["']?\s*[:=]`)
	staticNamePattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$`)
	staticNameYAMLPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,80}$`)
)

type candidate struct {
	path                 string
	line                 int
	name                 string
	kind                 string
	models               []string
	tools                []string
	identity             string
	identityLine         int
	mcpServer            string
	mcpLine              int
	mcpTransport         string
	mcpAuthMethod        string
	mcpTools             []string
	owner                string
	environment          string
	environmentExplicit  bool
	nameExplicit         bool
	readOnly             bool
	writeScope           bool
	permissionLine       int
	approvedServers      []string
	approvedProviders    []string
	modelLine            int
	productionCredential bool
	credentialLine       int
	sensitiveTool        bool
	sensitiveLine        int
	approvalMetadata     bool
	disablePath          bool
	disableLine          int
	verifiedAt           string
	verifiedLine         int
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
	policy := config.Default(".")
	if options.ConfigPath != "" {
		loaded, err := config.Load(options.ConfigPath)
		if err != nil {
			return Report{}, err
		}
		policy = loaded
	}
	freshnessDays := policy.FreshnessDays
	if freshnessDays <= 0 {
		freshnessDays = 30
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
			if ignoredDirectory(entry.Name()) || excludedDirectory(entry.Name(), policy.Exclude) {
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
	approvedProviders := map[string]bool{}
	for _, item := range candidates {
		for _, server := range item.approvedServers {
			approvedServers[strings.ToLower(server)] = true
		}
		for _, provider := range item.approvedProviders {
			approvedProviders[strings.ToLower(provider)] = true
		}
	}
	for _, server := range policy.ApprovedMCPServers {
		approvedServers[strings.ToLower(server)] = true
	}
	for _, provider := range policy.ApprovedProviders {
		approvedProviders[strings.ToLower(provider)] = true
	}

	sourceNames := map[string]bool{}
	for _, item := range candidates {
		if item.kind != "runtime" && item.kind != "registry" && item.kind != "mcp" && item.name != "" {
			sourceNames[strings.ToLower(item.name)] = true
		}
	}

	identityAgents := map[string][]Agent{}
	agentItems := map[string]candidate{}
	for _, item := range candidates {
		sourceType, trustLevel := "repository_file", "observed"
		if item.kind == "runtime" {
			sourceType, trustLevel = "runtime_metadata", "observed"
		} else if item.kind == "mcp" {
			sourceType, trustLevel = "mcp_metadata", "observed"
		} else if item.kind == "registry" {
			sourceType, trustLevel = "policy_registry", "declared"
		}
		report.Sources = append(report.Sources, Source{
			ID: stableID("source", item.path), Type: sourceType, Path: item.path, TrustLevel: trustLevel,
		})
	}

	for _, item := range candidates {
		if item.kind == "mcp" {
			if !containsMCPServer(report.MCPServers, item.mcpServer) {
				report.MCPServers = append(report.MCPServers, MCPServer{ID: stableID("mcp", strings.ToLower(item.mcpServer)), Name: item.mcpServer, Approved: approvedServers[strings.ToLower(item.mcpServer)], Transport: item.mcpTransport, AuthMethod: item.mcpAuthMethod, Tools: item.mcpTools, SourcePath: item.path})
			}
			continue
		}
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
		report.Relationships = append(report.Relationships, Relationship{
			ID: stableID("relationship", agentID+":discovered-from:"+item.path), FromType: "agent", FromID: agentID,
			EdgeType: "DISCOVERED_FROM", ToType: "source", ToID: stableID("source", item.path),
			Evidence: Evidence{Path: item.path, Line: item.line}, Confidence: agent.Confidence,
		})
		for _, modelName := range item.models {
			modelID := stableID("model", strings.ToLower(modelName))
			if !containsModel(report.Models, modelName) {
				report.Models = append(report.Models, Model{ID: modelID, Provider: modelProvider(modelName), Name: modelName, SourcePath: item.path})
			}
			report.Relationships = append(report.Relationships, Relationship{
				ID: stableID("relationship", agentID+":uses-model:"+modelID), FromType: "agent", FromID: agentID,
				EdgeType: "USES_MODEL", ToType: "model", ToID: modelID,
				Evidence: Evidence{Path: item.path, Line: item.modelLine}, Confidence: 0.75,
			})
		}
		if item.identity != "" {
			identityAgents[strings.ToLower(item.identity)] = append(identityAgents[strings.ToLower(item.identity)], agent)
			if !containsIdentity(report.Identities, item.identity) {
				report.Identities = append(report.Identities, Identity{ID: stableID("identity", strings.ToLower(item.identity)), Name: item.identity, SourcePath: item.path})
			}
			report.Relationships = append(report.Relationships, Relationship{
				ID: stableID("relationship", agentID+":authenticates-as:"+item.identity), FromType: "agent", FromID: agentID,
				EdgeType: "AUTHENTICATES_AS", ToType: "identity", ToID: stableID("identity", strings.ToLower(item.identity)),
				Evidence: Evidence{Path: item.path, Line: item.identityLine}, Confidence: 0.85,
			})
		}
		if item.mcpServer != "" && !containsMCPServer(report.MCPServers, item.mcpServer) {
			report.MCPServers = append(report.MCPServers, MCPServer{ID: stableID("mcp", strings.ToLower(item.mcpServer)), Name: item.mcpServer, Approved: approvedServers[strings.ToLower(item.mcpServer)], Transport: item.mcpTransport, AuthMethod: item.mcpAuthMethod, Tools: item.mcpTools, SourcePath: item.path})
		}
		if item.mcpServer != "" {
			report.Relationships = append(report.Relationships, Relationship{
				ID: stableID("relationship", agentID+":connects-to:"+item.mcpServer), FromType: "agent", FromID: agentID,
				EdgeType: "CONNECTS_TO", ToType: "mcp_server", ToID: stableID("mcp", strings.ToLower(item.mcpServer)),
				Evidence: Evidence{Path: item.path, Line: item.mcpLine}, Confidence: 0.80,
			})
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
		if item.productionCredential && strings.EqualFold(item.environment, "development") {
			report.Findings = append(report.Findings, Finding{
				ID: stableID("finding", agentID+":ACP-006"), RuleID: "ACP-006", Severity: "Critical",
				Message: "Development agent references a production credential",
				AgentID: agentID, Confidence: 0.90, Evidence: []Evidence{{Path: item.path, Line: item.credentialLine}},
				RemediationHint: "Use a development-scoped credential and verify that production credentials are unavailable in the development environment.",
			})
		}
		if item.sensitiveTool && !item.approvalMetadata {
			report.Findings = append(report.Findings, Finding{
				ID: stableID("finding", agentID+":ACP-007"), RuleID: "ACP-007", Severity: "High",
				Message: "Sensitive tool is declared without approval metadata",
				AgentID: agentID, Confidence: 0.82, Evidence: []Evidence{{Path: item.path, Line: item.sensitiveLine}},
				RemediationHint: "Record an approval, exception, or change ticket before enabling the sensitive tool.",
			})
		}
		if len(approvedProviders) > 0 {
			for _, modelName := range item.models {
				provider := modelProvider(modelName)
				if !approvedProviders[strings.ToLower(provider)] {
					report.Findings = append(report.Findings, Finding{
						ID: stableID("finding", agentID+":ACP-008:"+provider), RuleID: "ACP-008", Severity: "High",
						Message: fmt.Sprintf("Model provider %q is not present in the workspace policy", provider),
						AgentID: agentID, Confidence: 0.86, Evidence: []Evidence{{Path: item.path, Line: item.modelLine}},
						RemediationHint: "Use an approved provider or update the workspace policy through an explicit review.",
					})
				}
			}
		}
		if item.environmentExplicit && strings.EqualFold(item.environment, "production") && !item.disablePath {
			report.Findings = append(report.Findings, Finding{
				ID: stableID("finding", agentID+":ACP-009"), RuleID: "ACP-009", Severity: "High",
				Message: "Production agent has no documented disable or rollback path",
				AgentID: agentID, Confidence: 0.68, Evidence: []Evidence{{Path: item.path, Line: item.line}},
				RemediationHint: "Document and test a safe disable, rollback, or kill-switch procedure for the production agent.",
			})
		}
		if staleVerification(item.verifiedAt, freshnessDays) {
			report.Findings = append(report.Findings, Finding{
				ID: stableID("finding", agentID+":ACP-010"), RuleID: "ACP-010", Severity: "Medium",
				Message: "Agent verification metadata is stale",
				AgentID: agentID, Confidence: 0.88, Evidence: []Evidence{{Path: item.path, Line: item.verifiedLine}},
				RemediationHint: "Re-verify the agent, identity, permissions, and owner, then update the verification date.",
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
	if ignoredSourceFile(relative) {
		return nil, nil
	}
	if candidate, err := inspectJSONMCPMetadata(path, relative); err != nil || candidate != nil {
		return candidate, err
	}
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
	environmentExplicit := false
	nameExplicit := false
	var mcpTransport, mcpAuthMethod, verifiedAt string
	identityLine, mcpLine, permissionLine := 0, 0, 0
	modelLine, credentialLine, sensitiveLine, disableLine, verifiedLine := 0, 0, 0, 0, 0
	readOnly, writeScope := false, false
	productionCredential, sensitiveTool, approvalMetadata, disablePath := false, false, false, false
	approvedServers, approvedProviders, mcpTools := []string{}, []string{}, []string{}
	firstSignal := 0
	frameworkSignal := false
	modelDeclarationSignal := false
	scannerImplementation := false
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.Contains(line, "regexp.MustCompile") {
			// Do not let the scanner's own detection vocabulary become inventory.
			scannerImplementation = true
			continue
		}
		if productionCredentialPattern.MatchString(line) {
			productionCredential = true
			if credentialLine == 0 {
				credentialLine = lineNumber
			}
		}
		if sensitiveToolPattern.MatchString(line) {
			sensitiveTool = true
			if sensitiveLine == 0 {
				sensitiveLine = lineNumber
			}
		}
		if approvalPattern.MatchString(line) {
			approvalMetadata = true
		}
		if disablePathPattern.MatchString(line) {
			disablePath = true
			if disableLine == 0 {
				disableLine = lineNumber
			}
		}
		if declarationMatch(line, verifiedPattern) && verifiedAt == "" {
			verifiedAt = declarationValue(line, verifiedPattern)
			verifiedLine = lineNumber
		}
		if secretPattern.MatchString(line) {
			// Never copy or emit the line. The scanner only retains safe metadata.
			continue
		}
		if name == "" && declarationMatch(line, namePattern) {
			name = declarationValue(line, namePattern)
			nameExplicit = name != "" && name != "unknown" && staticNameDeclaration(line)
			if firstSignal == 0 && nameExplicit && isAgentPath(relative) && isAgentName(name) {
				firstSignal = lineNumber
			}
		}
		if identity == "" && declarationMatch(line, identityPattern) {
			identity = declarationValue(line, identityPattern)
			identityLine = lineNumber
		}
		if mcpServer == "" && declarationMatch(line, mcpPattern) {
			mcpServer = declarationValue(line, mcpPattern)
			mcpLine = lineNumber
		}
		if mcpServer != "" && mcpTransport == "" && declarationMatch(line, transportPattern) {
			mcpTransport = declarationValue(line, transportPattern)
		}
		if mcpServer != "" && mcpAuthMethod == "" && declarationMatch(line, authMethodPattern) {
			mcpAuthMethod = declarationValue(line, authMethodPattern)
		}
		if readOnlyPattern.MatchString(line) {
			readOnly = true
		}
		if writePattern.MatchString(line) && (declarationMatch(line, toolPattern) || declarationMatch(line, permissionDeclaration)) {
			writeScope = true
			permissionLine = lineNumber
		}
		if strings.Contains(strings.ToLower(relative), "approved") && strings.Contains(strings.ToLower(relative), "mcp") {
			if match := listItemPattern.FindStringSubmatch(line); len(match) == 2 {
				approvedServers = appendUnique(approvedServers, match[1])
			}
		}
		if strings.Contains(strings.ToLower(relative), "approved") && strings.Contains(strings.ToLower(relative), "provider") {
			if match := listItemPattern.FindStringSubmatch(line); len(match) == 2 {
				approvedProviders = appendUnique(approvedProviders, match[1])
			}
		}
		if mcpServer != "" && declarationMatch(line, toolPattern) {
			mcpTools = appendUnique(mcpTools, toolLabel(line))
		}
		if firstSignal == 0 && (frameworkPattern.MatchString(line) || modelPattern.MatchString(line) || declarationMatch(line, modelDeclaration) || declarationMatch(line, toolPattern) || sensitiveTool) {
			firstSignal = lineNumber
		}
		if declarationMatch(line, modelDeclaration) {
			modelDeclarationSignal = true
			if value := declarationValue(line, modelDeclaration); value != "" && value != "unknown" {
				models = appendUnique(models, value)
				if modelLine == 0 {
					modelLine = lineNumber
				}
			}
		} else if modelPattern.MatchString(line) {
			models = appendUnique(models, modelLabel(line))
			if modelLine == 0 {
				modelLine = lineNumber
			}
		}
		if frameworkPattern.MatchString(line) {
			frameworkSignal = true
		}
		if declarationMatch(line, toolPattern) {
			tools = appendUnique(tools, toolLabel(line))
		}
		if owner == "" && declarationMatch(line, ownerPattern) {
			owner = declarationValue(line, ownerPattern)
		}
		if environment == "" && declarationMatch(line, environmentPattern) {
			environmentExplicit = true
			value := strings.ToLower(declarationValue(line, environmentPattern))
			switch value {
			case "prod":
				environment = "production"
			case "dev":
				environment = "development"
			default:
				environment = value
			}
		}
		if environment == "" && productionComment.MatchString(line) {
			environment = "production"
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if scannerImplementation {
		return nil, nil
	}
	if firstSignal == 0 && identity == "" && mcpServer == "" && len(approvedServers) == 0 && len(approvedProviders) == 0 && !runtimeMetadataPath(relative) {
		return nil, nil
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(relative), filepath.Ext(relative))
	}
	kind := "source"
	if len(approvedServers) > 0 || len(approvedProviders) > 0 {
		kind = "registry"
	} else if runtimeMetadataPath(relative) {
		kind = "runtime"
	}
	if kind == "source" && !isLikelyAgentCandidate(relative, name, nameExplicit, modelDeclarationSignal, frameworkSignal, models, identity, mcpServer, environmentExplicit) {
		return nil, nil
	}
	if firstSignal == 0 {
		firstSignal = 1
	}
	return &candidate{
		path: relative, line: firstSignal, name: name, kind: kind, models: models, tools: tools,
		identity: identity, identityLine: identityLine, mcpServer: mcpServer, mcpLine: mcpLine,
		mcpTransport: mcpTransport, mcpAuthMethod: mcpAuthMethod, mcpTools: mcpTools,
		owner: owner, environment: environment, environmentExplicit: environmentExplicit, nameExplicit: nameExplicit, readOnly: readOnly, writeScope: writeScope,
		permissionLine: permissionLine, approvedServers: approvedServers, approvedProviders: approvedProviders,
		modelLine: modelLine, productionCredential: productionCredential, credentialLine: credentialLine,
		sensitiveTool: sensitiveTool, sensitiveLine: sensitiveLine, approvalMetadata: approvalMetadata,
		disablePath: disablePath, disableLine: disableLine, verifiedAt: verifiedAt, verifiedLine: verifiedLine,
	}, nil
}

func inspectJSONMCPMetadata(path, relative string) (*candidate, error) {
	base := strings.ToLower(filepath.Base(relative))
	if base != ".mcp.json" && base != "server.json" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, nil
	}
	if base == ".mcp.json" {
		servers, ok := document["mcpServers"].(map[string]any)
		if !ok || len(servers) == 0 {
			return nil, nil
		}
		names := make([]string, 0, len(servers))
		for name := range servers {
			names = append(names, name)
		}
		sort.Strings(names)
		name := names[0]
		entry, _ := servers[name].(map[string]any)
		transport := stringValue(entry["type"])
		if transport == "" && stringValue(entry["url"]) != "" {
			transport = "http"
		}
		return &candidate{
			path: relative, line: lineForValue(data, name), name: name, kind: "mcp",
			mcpServer: name, mcpLine: lineForValue(data, name), mcpTransport: transport,
			mcpAuthMethod: jsonAuthMethod(entry),
		}, nil
	}

	name := stringValue(document["name"])
	if name == "" {
		return nil, nil
	}
	transport := ""
	if packages, ok := document["packages"].([]any); ok {
		for _, rawPackage := range packages {
			pkg, _ := rawPackage.(map[string]any)
			transportBlock, _ := pkg["transport"].(map[string]any)
			if transport = stringValue(transportBlock["type"]); transport != "" {
				break
			}
		}
	}
	if transport == "" {
		if remotes, ok := document["remotes"].([]any); ok && len(remotes) > 0 {
			remote, _ := remotes[0].(map[string]any)
			transport = stringValue(remote["type"])
		}
	}
	return &candidate{
		path: relative, line: lineForValue(data, name), name: name, kind: "mcp",
		mcpServer: name, mcpLine: lineForValue(data, name), mcpTransport: transport,
		mcpAuthMethod: jsonManifestAuthMethod(document),
	}, nil
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func jsonAuthMethod(entry map[string]any) string {
	if _, ok := entry["headers"]; ok {
		return "header"
	}
	if _, ok := entry["env"]; ok {
		return "environment"
	}
	return ""
}

func jsonManifestAuthMethod(document map[string]any) string {
	remotes, ok := document["remotes"].([]any)
	if !ok || len(remotes) == 0 {
		return ""
	}
	remote, _ := remotes[0].(map[string]any)
	return jsonAuthMethod(remote)
}

func lineForValue(data []byte, value string) int {
	if value == "" {
		return 1
	}
	needle := []byte(value)
	for index := 0; index+len(needle) <= len(data); index++ {
		if string(data[index:index+len(needle)]) == value {
			line := 1
			for _, current := range data[:index] {
				if current == '\n' {
					line++
				}
			}
			return line
		}
	}
	return 1
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
	case ".agentctl", ".claude", ".github", ".git", ".hg", ".svn", ".storybook", "__tests__", "e2e", "test-servers", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__", "examples", "example", "samples", "sample", "demos", "demo", "tutorials", "tutorial", "docs_src", "tests", "test", "testdata", "fixtures", "benchmarks", "docs", "doc", "schemas", "schema":
		return true
	default:
		return false
	}
}

func ignoredSourceFile(relative string) bool {
	base := strings.ToLower(filepath.Base(relative))
	return strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.Contains(base, ".stories.")
}

func runtimeMetadataPath(relative string) bool {
	if !runtimePattern.MatchString(relative) {
		return false
	}
	switch strings.ToLower(filepath.Ext(relative)) {
	case ".json", ".yaml", ".yml", ".toml":
		return true
	default:
		return false
	}
}

func isLikelyAgentCandidate(relative, name string, nameExplicit, modelDeclarationSignal, frameworkSignal bool, models []string, identity, mcpServer string, environmentExplicit bool) bool {
	if isLibrarySourcePath(relative) && !environmentExplicit {
		return false
	}
	if nameExplicit && isAgentPath(relative) && isAgentName(name) {
		return true
	}
	if !isAgentPath(relative) || !isAgentEntryFile(relative) {
		return false
	}
	if identity != "" || mcpServer != "" || environmentExplicit {
		return true
	}
	return len(models) > 0 && (modelDeclarationSignal || frameworkSignal)
}

func staticNameDeclaration(line string) bool {
	delimiter := ":"
	parts := strings.SplitN(line, delimiter, 2)
	if len(parts) != 2 {
		delimiter = "="
		parts = strings.SplitN(line, delimiter, 2)
	}
	if len(parts) != 2 {
		return false
	}
	right := strings.TrimSpace(parts[1])
	if len(right) >= 2 && strings.ContainsRune("`\"'", rune(right[0])) {
		return true
	}
	if delimiter == ":" {
		return staticNameYAMLPattern.MatchString(right)
	}
	return staticNamePattern.MatchString(strings.Trim(right, "`\"'"))
}

func isLibrarySourcePath(relative string) bool {
	for _, part := range strings.Split(strings.ToLower(filepath.ToSlash(relative)), "/") {
		switch part {
		case "lib", "libs", "packages":
			return true
		}
	}
	return false
}

func isAgentEntryFile(relative string) bool {
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(relative)), filepath.Ext(relative))
	for _, marker := range []string{"agent", "assistant", "copilot", "chatbot", "bot", "worker", "runner"} {
		if strings.Contains(base, marker) {
			return true
		}
	}
	switch base {
	case "", "base", "__init__", "prompt", "prompts", "toolkit", "output_parser", "parser", "types", "models", "model", "context", "utils", "registry", "config", "schema", "manager", "middleware", "helpers", "constants", "version", "settings", "loading", "component", "api", "server", "client", "connection", "state", "states":
		return false
	default:
		return isAgentPath(relative)
	}
}

func isAgentName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"agent", "assistant", "copilot", "chatbot", "bot"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isAgentPath(relative string) bool {
	for _, part := range strings.Split(strings.ToLower(filepath.ToSlash(relative)), "/") {
		for _, marker := range []string{"agent", "assistant", "copilot", "chatbot", "bot", "crew", "autogen", "langgraph"} {
			if strings.Contains(part, marker) {
				return true
			}
		}
	}
	return false
}

func excludedDirectory(name string, exclusions []string) bool {
	for _, exclusion := range exclusions {
		if strings.EqualFold(strings.Trim(strings.TrimSpace(exclusion), "/"), name) {
			return true
		}
	}
	return false
}

func declarationValue(line string, pattern *regexp.Regexp) string {
	if !declarationMatch(line, pattern) {
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

func declarationMatch(line string, pattern *regexp.Regexp) bool {
	return pattern.MatchString(line) && !strings.Contains(strings.TrimSpace(line), ":=")
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

func containsModel(values []Model, name string) bool {
	for _, value := range values {
		if strings.EqualFold(value.Name, name) {
			return true
		}
	}
	return false
}

func modelProvider(model string) string {
	lower := strings.ToLower(strings.TrimSpace(model))
	for _, provider := range []string{"openai", "anthropic", "claude", "gemini", "vertexai", "bedrock", "ollama", "litellm"} {
		if strings.Contains(lower, provider) {
			if provider == "claude" {
				return "anthropic"
			}
			return provider
		}
	}
	for _, separator := range []string{"/", ":", "@"} {
		if index := strings.Index(lower, separator); index > 0 {
			return strings.TrimSpace(lower[:index])
		}
	}
	return lower
}

func staleVerification(value string, freshnessDays int) bool {
	if value == "" || value == "unknown" {
		return false
	}
	if freshnessDays <= 0 {
		freshnessDays = 30
	}
	verifiedAt, err := time.Parse("2006-01-02", strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return time.Since(verifiedAt) > time.Duration(freshnessDays)*24*time.Hour
}

func stableID(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + ":" + value))
	return fmt.Sprintf("%s_%x", kind, sum[:8])
}
