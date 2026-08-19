package scan

import (
	"encoding/json"
	"sort"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifMessage       `json:"message"`
	Locations    []sarifLocation    `json:"locations,omitempty"`
	Properties   map[string]any     `json:"properties,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// SARIF returns a deterministic SARIF 2.1.0 log for the report findings.
func (r Report) SARIF() ([]byte, error) {
	ruleNames := map[string]string{}
	for _, finding := range r.Findings {
		if _, exists := ruleNames[finding.RuleID]; !exists {
			ruleNames[finding.RuleID] = finding.Message
		}
	}
	rules := make([]sarifRule, 0, len(ruleNames))
	for ruleID, description := range ruleNames {
		rules = append(rules, sarifRule{
			ID:               ruleID,
			Name:             ruleID,
			ShortDescription: sarifMessage{Text: description},
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	results := make([]sarifResult, 0, len(r.Findings))
	for _, finding := range r.Findings {
		locations := make([]sarifLocation, 0, len(finding.Evidence))
		for _, evidence := range finding.Evidence {
			line := evidence.Line
			if line < 1 {
				line = 1
			}
			locations = append(locations, sarifLocation{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: evidence.Path},
				Region:           sarifRegion{StartLine: line},
			}})
		}
		properties := map[string]any{
			"agent_id":         finding.AgentID,
			"confidence":       finding.Confidence,
			"remediation_hint": finding.RemediationHint,
		}
		result := sarifResult{
			RuleID:     finding.RuleID,
			Level:      sarifLevel(finding.Severity),
			Message:    sarifMessage{Text: finding.Message},
			Locations:  locations,
			Properties: properties,
		}
		if finding.Suppressed {
			result.Suppressions = []sarifSuppression{{Kind: "external", Justification: finding.SuppressionReason}}
			properties["suppression_expires_at"] = finding.SuppressionExpiresAt
		}
		results = append(results, result)
	}

	payload := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Agent Control Plane",
				Version:        schemaVersion,
				InformationURI: "https://github.com/HlinorAI/agent-control-plane",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(payload, "", "  ")
}

func sarifLevel(severity string) string {
	switch severity {
	case "Critical", "High":
		return "error"
	case "Medium":
		return "warning"
	default:
		return "note"
	}
}
