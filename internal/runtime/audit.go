package runtime

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/HlinorAI/agent-control-plane/internal/scan"
)

type Finding struct {
	ID              string   `json:"id"`
	RuleID          string   `json:"rule_id"`
	Severity        string   `json:"severity"`
	Message         string   `json:"message"`
	AgentID         string   `json:"agent_id,omitempty"`
	Confidence      float64  `json:"confidence"`
	Evidence        []string `json:"evidence,omitempty"`
	RemediationHint string   `json:"remediation_hint"`
}

type AuditReport struct {
	SchemaVersion string    `json:"schema_version"`
	Runtime       Report    `json:"runtime"`
	MatchedAgents int       `json:"matched_agents"`
	Unmatched     int       `json:"unmatched_agents"`
	Findings      []Finding `json:"findings"`
}

func Audit(runtimeReport Report, inventory scan.Report) AuditReport {
	result := AuditReport{SchemaVersion: "runtime-audit.v1", Runtime: runtimeReport}
	byID := make(map[string]scan.Agent, len(inventory.Agents))
	byName := make(map[string][]scan.Agent)
	for _, agent := range inventory.Agents {
		byID[agent.ID] = agent
		name := strings.ToLower(strings.TrimSpace(agent.Name))
		if name != "" {
			byName[name] = append(byName[name], agent)
		}
	}
	providers := make(map[string]bool)
	for _, model := range inventory.Models {
		providers[strings.ToLower(strings.TrimSpace(model.Provider))] = true
	}

	for _, summary := range runtimeReport.Agents {
		agent, ok := matchAgent(summary, byID, byName)
		if !ok {
			result.Unmatched++
			result.Findings = append(result.Findings, Finding{
				RuleID: "ACP-R004", Severity: "Medium", Message: fmt.Sprintf("runtime activity for %q cannot be matched uniquely to static inventory", runtimeAgentLabel(summary)), Confidence: 0.92,
				Evidence: []string{summary.FirstSeen.Format("2006-01-02T15:04:05Z07:00"), summary.LastSeen.Format("2006-01-02T15:04:05Z07:00")}, RemediationHint: "Emit the stable static agent ID in runtime telemetry.",
			})
			continue
		}
		result.MatchedAgents++
		declaredTargets := make(map[string]bool)
		for _, target := range agent.Tools {
			declaredTargets[strings.ToLower(strings.TrimSpace(target))] = true
		}
		for _, target := range summary.Targets {
			if !declaredTargets[strings.ToLower(strings.TrimSpace(target))] {
				result.Findings = append(result.Findings, Finding{
					RuleID: "ACP-R001", Severity: "High", Message: fmt.Sprintf("agent %q used undeclared runtime target %q", agent.Name, target), AgentID: agent.ID, Confidence: 0.90,
					Evidence: []string{target, summary.LastSeen.Format("2006-01-02T15:04:05Z07:00")}, RemediationHint: "Declare the target in the agent inventory or investigate the unexpected integration.",
				})
			}
		}
		for _, provider := range summary.Providers {
			if provider != "" && !providers[strings.ToLower(strings.TrimSpace(provider))] {
				result.Findings = append(result.Findings, Finding{
					RuleID: "ACP-R002", Severity: "High", Message: fmt.Sprintf("agent %q used provider %q not present in static model inventory", agent.Name, provider), AgentID: agent.ID, Confidence: 0.86,
					Evidence: []string{provider, summary.LastSeen.Format("2006-01-02T15:04:05Z07:00")}, RemediationHint: "Verify the provider and update workspace policy or runtime configuration.",
				})
			}
		}
		if summary.WriteEvents > 0 && hasProduction(summary.Environments) {
			undeclaredWrite := false
			for _, target := range summary.Targets {
				if !declaredTargets[strings.ToLower(strings.TrimSpace(target))] {
					undeclaredWrite = true
				}
			}
			if undeclaredWrite {
				result.Findings = append(result.Findings, Finding{
					RuleID: "ACP-R003", Severity: "Critical", Message: fmt.Sprintf("production agent %q performed write activity against an undeclared target", agent.Name), AgentID: agent.ID, Confidence: 0.94,
					Evidence: []string{summary.LastSeen.Format("2006-01-02T15:04:05Z07:00")}, RemediationHint: "Block or review the write path and declare an approved least-privilege scope.",
				})
			}
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		left := result.Findings[i].RuleID + ":" + result.Findings[i].AgentID + ":" + result.Findings[i].Message
		right := result.Findings[j].RuleID + ":" + result.Findings[j].AgentID + ":" + result.Findings[j].Message
		return left < right
	})
	for i := range result.Findings {
		result.Findings[i].ID = findingID(result.Findings[i])
	}
	return result
}

func matchAgent(summary AgentSummary, byID map[string]scan.Agent, byName map[string][]scan.Agent) (scan.Agent, bool) {
	if agent, ok := byID[summary.AgentID]; ok && summary.AgentID != "" {
		return agent, true
	}
	matches := byName[strings.ToLower(strings.TrimSpace(summary.AgentName))]
	if len(matches) == 1 {
		return matches[0], true
	}
	return scan.Agent{}, false
}

func runtimeAgentLabel(summary AgentSummary) string {
	if summary.AgentName != "" {
		return summary.AgentName
	}
	return summary.AgentID
}

func hasProduction(environments []string) bool {
	for _, environment := range environments {
		if strings.EqualFold(environment, "production") || strings.EqualFold(environment, "prod") {
			return true
		}
	}
	return false
}

func findingID(finding Finding) string {
	sum := sha256.Sum256([]byte(finding.RuleID + ":" + finding.AgentID + ":" + finding.Message))
	return fmt.Sprintf("runtime_%x", sum[:8])
}
