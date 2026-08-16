package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HlinorAI/agent-control-plane/internal/config"
)

func TestRunDetectsAgentAndOwnerGapWithoutEmittingSecret(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "agents", "crm_agent.py")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	content := `# production agent
model = "openai"
MCP_TOOL = "crm.search"
API_KEY = "super-secret-value"
`
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.ReadOnly || !report.MetadataOnly {
		t.Fatalf("expected read-only metadata-only report: %+v", report)
	}
	if len(report.Agents) != 1 || len(report.Findings) != 1 {
		t.Fatalf("expected one agent and one finding, got %d and %d", len(report.Agents), len(report.Findings))
	}
	if report.Findings[0].RuleID != "ACP-001" || report.Findings[0].Severity != "High" {
		t.Fatalf("unexpected finding: %+v", report.Findings[0])
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "super-secret-value") || strings.Contains(string(encoded), "API_KEY") {
		t.Fatalf("report leaked secret material: %s", encoded)
	}
}

func TestRunDryRunDoesNotParseContent(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "agent.ts")
	if err := os.WriteFile(file, []byte("agent = openai(); MCP_TOOL = true"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 || len(report.Agents) != 0 || len(report.Findings) != 0 {
		t.Fatalf("dry-run parsed content: %+v", report)
	}
	if len(report.ReadFiles) != 1 || report.ReadFiles[0] != "agent.ts" {
		t.Fatalf("unexpected dry-run files: %+v", report.ReadFiles)
	}
}

func TestRunDoesNotInventoryRootDocumentation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("production agent uses MCP and OpenAI"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 || len(report.Agents) != 0 || len(report.Findings) != 0 {
		t.Fatalf("root documentation should be scanned without inventorying an agent: %+v", report)
	}
}

func TestRunIgnoresScannerImplementationVocabulary(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "scanner.go")
	content := `package scan

var modelProvider = "openai"
var writeScope = true
var mcpServer = "internal"
var message = "production agent uses tools"
`
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Agents) != 0 || len(report.Findings) != 0 {
		t.Fatalf("implementation vocabulary was inventoried as an agent: %+v", report)
	}
}

func TestRunIgnoresScannerImplementationFile(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "scanner.go")
	content := `package scan

var providerPattern = regexp.MustCompile("openai")
model = "openai"
MCP_TOOL = "internal"
`
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Agents) != 0 || len(report.Findings) != 0 {
		t.Fatalf("scanner implementation file was inventoried: %+v", report)
	}
}

func TestRunIgnoresFixturesAndRuntimeImplementationCode(t *testing.T) {
	root := t.TempDir()
	exampleDir := filepath.Join(root, "examples")
	if err := os.MkdirAll(exampleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(exampleDir, "agent.py"), []byte("name: example-agent\nmodel: openai\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "runner.py"), []byte("name: runtime-worker\nmodel: openai\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "agents.json"), []byte("name: runtime-agent\nmodel: openai\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Agents) != 0 || len(report.Sources) != 1 {
		t.Fatalf("fixture/runtime implementation code was inventoried: %+v", report)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "ACP-002" {
		t.Fatalf("expected only runtime metadata drift finding: %+v", report.Findings)
	}
}

func TestRunDetectsFrameworkLibraryAgentsAndIgnoresSamples(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"lib/framework/agents/base.py":                        "from crewai import Agent\nmodel = \"openai/gpt-4o\"\n",
		"libs/framework/agents/base.py":                       "from langchain_openai import ChatOpenAI\nmodel = ChatOpenAI()\ntools: list = []\n",
		"packages/framework/agents/openai_assistant_agent.py": "from autogen import AssistantAgent\nmodel = \"openai/gpt-4o\"\n",
		"samples/agent.py":                                    "name: sample-agent\nmodel: openai\n",
		"docs_src/tutorial.py":                                "mcp_server: demo\nmodel: openai\n",
	}
	for relative, content := range files {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Agents) != 1 || report.Agents[0].SourcePath != "packages/framework/agents/openai_assistant_agent.py" {
		t.Fatalf("expected the concrete framework agent entry to be inventoried: %+v", report.Agents)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "ACP-001" || report.Findings[0].Severity != "Note" {
		t.Fatalf("expected only an informational owner gap: %+v", report.Findings)
	}
}

func TestRunCollectsAllMCPServersAndAppliesApprovalRule(t *testing.T) {
	root := t.TempDir()
	clientConfig := `{"mcpServers":{"docs":{"type":"http","url":"https://example.test/mcp"},"unknown":{"command":"npx","args":["-y","untrusted-server"]}}}`
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(clientConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(root, ".agentctl", "config.yaml")
	policy := config.Default(".")
	policy.ApprovedMCPServers = []string{"docs"}
	if err := config.WriteDefault(policyPath, policy); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{ConfigPath: policyPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MCPServers) != 2 || len(report.Sources) != 1 {
		t.Fatalf("expected both MCP servers and one deduplicated source, got servers=%+v sources=%+v", report.MCPServers, report.Sources)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "ACP-005" {
		t.Fatalf("expected one unapproved MCP finding, got %+v", report.Findings)
	}
	if report.Findings[0].Evidence[0].Path != ".mcp.json" || report.Findings[0].Evidence[0].Line < 1 {
		t.Fatalf("expected MCP source evidence, got %+v", report.Findings[0].Evidence)
	}
}

func TestRunDiscoversAgentMarkdownUnderToolingDirectories(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		".claude/agents/support-agent.md": "name: support-agent\nmodel: openai\nowner: platform\n",
		".github/agents/release-agent.md": "name: release-agent\nmodel: openai\nowner: release\n",
	}
	for relative, content := range files {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Agents) != 2 || len(report.Findings) != 0 {
		t.Fatalf("expected two owned Markdown agents without findings: agents=%+v findings=%+v", report.Agents, report.Findings)
	}
}

func TestRunDoesNotInventoryGenericGitHubWorkflow(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "agentctl-pr.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	content := "name: Agent Control Plane pull request scan\non: [pull_request]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Agents) != 0 || len(report.Findings) != 0 {
		t.Fatalf("generic GitHub workflow was inventoried as an agent: %+v", report)
	}
}

func TestRunDetectsDeclarativeAgentRegistryEntry(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "registry", "agents", "ticket-triage-agent.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	content := "type: agent\nname: Ticket Triage Agent\nmodel: openai/gpt-4o\nowner: support-platform\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Agents) != 1 || report.Agents[0].Name != "Ticket Triage Agent" {
		t.Fatalf("declarative registry agent was not detected: %+v", report.Agents)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("unexpected findings for owned registry agent: %+v", report.Findings)
	}
}

func TestRunRegressionFixtures(t *testing.T) {
	report, err := Run(filepath.Join("..", "..", "testdata", "regression"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Agents) != 2 {
		t.Fatalf("unexpected regression inventory: %+v", report.Agents)
	}
	foundRegistryAgent := false
	for _, agent := range report.Agents {
		if agent.Name == "Ticket Triage Agent" && agent.SourcePath == "registry/agents/ticket-triage-agent.yaml" {
			foundRegistryAgent = true
		}
	}
	if !foundRegistryAgent {
		t.Fatalf("declarative registry agent was not preserved: %+v", report.Agents)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "ACP-001" || report.Findings[0].Severity != "Note" {
		t.Fatalf("expected only an informational owner gap for the library agent: %+v", report.Findings)
	}
}

func TestRunCollectsMCPJSONMetadata(t *testing.T) {
	root := t.TempDir()
	clientConfig := `{"mcpServers":{"docs":{"type":"http","url":"https://example.test/mcp"}}}`
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(clientConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	serverManifest := `{"name":"io.example/demo-server","packages":[{"transport":{"type":"stdio"}}],"remotes":[{"type":"streamable-http","headers":[{"name":"Authorization","isSecret":true}]}]}`
	if err := os.WriteFile(filepath.Join(root, "server.json"), []byte(serverManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MCPServers) != 2 || len(report.Sources) != 2 || len(report.Agents) != 0 {
		t.Fatalf("unexpected MCP metadata inventory: %+v", report)
	}
	servers := map[string]string{}
	for _, server := range report.MCPServers {
		servers[server.Name] = server.Transport
	}
	if servers["docs"] != "http" || servers["io.example/demo-server"] != "stdio" {
		t.Fatalf("unexpected MCP transports: %+v", servers)
	}
	for _, server := range report.MCPServers {
		if server.Name == "io.example/demo-server" && server.AuthMethod != "header" {
			t.Fatalf("expected safe header auth metadata: %+v", server)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "Authorization") || strings.Contains(string(encoded), "example.test/mcp") {
		t.Fatalf("MCP report leaked config payload: %s", encoded)
	}
}

func TestSARIFIncludesEmptyResultsArray(t *testing.T) {
	payload, err := (Report{Findings: []Finding{}}).SARIF()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"results": []`) {
		t.Fatalf("SARIF omitted the empty results array: %s", payload)
	}
}

func TestRunDemoFixtureFindsRiskRulesAndCanonicalRelationships(t *testing.T) {
	report, err := Run(filepath.Join("..", "..", "testdata", "demo"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"ACP-001": false, "ACP-002": false, "ACP-003": false, "ACP-004": false, "ACP-005": false,
		"ACP-006": false, "ACP-007": false, "ACP-008": false, "ACP-009": false, "ACP-010": false,
	}
	for _, finding := range report.Findings {
		if _, ok := wanted[finding.RuleID]; ok {
			wanted[finding.RuleID] = true
		}
	}
	for ruleID, found := range wanted {
		if !found {
			t.Fatalf("demo fixture did not produce %s; findings=%+v", ruleID, report.Findings)
		}
	}
	if len(report.Agents) != 3 || len(report.Sources) != 6 || len(report.Models) != 3 {
		t.Fatalf("unexpected canonical inventory sizes: agents=%d sources=%d models=%d", len(report.Agents), len(report.Sources), len(report.Models))
	}
	if len(report.Identities) != 2 || report.Identities[0].Name != "shared-crm-role" && report.Identities[1].Name != "shared-crm-role" {
		t.Fatalf("expected shared identity inventory, got %+v", report.Identities)
	}
	edges := map[string]bool{}
	for _, relationship := range report.Relationships {
		edges[relationship.EdgeType] = true
	}
	for _, edge := range []string{"DISCOVERED_FROM", "USES_MODEL", "AUTHENTICATES_AS", "CONNECTS_TO"} {
		if !edges[edge] {
			t.Fatalf("missing canonical relationship %s: %+v", edge, report.Relationships)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "prod-api-token") {
		t.Fatalf("report leaked production credential material: %s", encoded)
	}
}

func TestRunProducesStableReport(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "demo")
	first, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("same inputs produced different reports\nfirst: %s\nsecond: %s", firstJSON, secondJSON)
	}
}

func TestRunUsesWorkspacePolicyConfig(t *testing.T) {
	root := t.TempDir()
	agentPath := filepath.Join(root, "agent.py")
	if err := os.WriteFile(agentPath, []byte("name: policy-agent\nmodel: internal-provider/model-x\nenvironment: production\nmcp_server: approved-crm\nlast_verified: 2026-08-10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ignoredDir := filepath.Join(root, "ignored")
	if err := os.MkdirAll(ignoredDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ignoredDir, "agent.py"), []byte("model: unapproved-provider\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(root, ".agentctl", "config.yaml")
	policy := config.Default(".")
	policy.Exclude = append(policy.Exclude, "ignored")
	policy.FreshnessDays = 1
	policy.ApprovedProviders = []string{"internal-provider"}
	policy.ApprovedMCPServers = []string{"approved-crm"}
	if err := config.WriteDefault(policyPath, policy); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root, Options{ConfigPath: policyPath})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 {
		t.Fatalf("policy exclusion was not applied: %+v", report.ReadFiles)
	}
	for _, finding := range report.Findings {
		if finding.RuleID == "ACP-005" || finding.RuleID == "ACP-008" {
			t.Fatalf("workspace policy was not applied: %+v", report.Findings)
		}
	}
	foundStale := false
	for _, finding := range report.Findings {
		if finding.RuleID == "ACP-010" {
			foundStale = true
		}
	}
	if !foundStale {
		t.Fatalf("freshness policy did not affect stale verification: %+v", report.Findings)
	}
}
