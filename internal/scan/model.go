package scan

import (
	"fmt"
	"sort"
	"strings"
)

const schemaVersion = "0.1"

type Options struct {
	DryRun bool
}

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Root          string    `json:"root"`
	ReadOnly      bool      `json:"read_only"`
	MetadataOnly  bool      `json:"metadata_only"`
	FilesScanned  int       `json:"files_scanned"`
	FilesSkipped  int       `json:"files_skipped"`
	Agents        []Agent   `json:"agents"`
	Findings      []Finding `json:"findings"`
	ReadFiles     []string  `json:"read_files,omitempty"`
}

type Agent struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	SourcePath  string   `json:"source_path"`
	Models      []string `json:"models,omitempty"`
	Tools       []string `json:"tools,omitempty"`
	Environment string   `json:"environment,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Confidence  float64  `json:"confidence"`
}

type Finding struct {
	ID              string     `json:"id"`
	RuleID          string     `json:"rule_id"`
	Severity        string     `json:"severity"`
	Message         string     `json:"message"`
	AgentID         string     `json:"agent_id"`
	Confidence      float64    `json:"confidence"`
	Evidence        []Evidence `json:"evidence"`
	RemediationHint string     `json:"remediation_hint"`
}

type Evidence struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Agent Control Plane scan\nRoot: %s\nRead-only: %t\nMetadata-only: %t\nFiles: %d scanned, %d skipped\nAgents: %d\nFindings: %d\n", r.Root, r.ReadOnly, r.MetadataOnly, r.FilesScanned, r.FilesSkipped, len(r.Agents), len(r.Findings))
	if len(r.ReadFiles) > 0 {
		b.WriteString("\nRead files:\n")
		for _, path := range r.ReadFiles {
			fmt.Fprintf(&b, "- %s\n", path)
		}
	}
	if len(r.Agents) > 0 {
		b.WriteString("\nAgents:\n")
		for _, agent := range r.Agents {
			fmt.Fprintf(&b, "- %s (%s) confidence=%.2f", agent.Name, agent.SourcePath, agent.Confidence)
			if len(agent.Models) > 0 {
				fmt.Fprintf(&b, " models=%s", strings.Join(agent.Models, ","))
			}
			if len(agent.Tools) > 0 {
				fmt.Fprintf(&b, " tools=%s", strings.Join(agent.Tools, ","))
			}
			b.WriteByte('\n')
		}
	}
	if len(r.Findings) > 0 {
		b.WriteString("\nFindings:\n")
		for _, finding := range r.Findings {
			fmt.Fprintf(&b, "- [%s] %s: %s\n", finding.Severity, finding.RuleID, finding.Message)
			for _, evidence := range finding.Evidence {
				fmt.Fprintf(&b, "  evidence: %s:%d\n", evidence.Path, evidence.Line)
			}
		}
	}
	return b.String()
}

func sortReport(r *Report) {
	sort.Slice(r.Agents, func(i, j int) bool { return r.Agents[i].ID < r.Agents[j].ID })
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
	sort.Strings(r.ReadFiles)
}
