package policy

import (
	"sort"
	"strings"

	"github.com/HlinorAI/agent-control-plane/internal/cloudaudit"
	"github.com/HlinorAI/agent-control-plane/internal/runtime"
)

type Draft struct {
	SchemaVersion  string   `json:"schema_version"`
	AgentID        string   `json:"agent_id"`
	Environment    string   `json:"environment,omitempty"`
	AllowedTargets []string `json:"allowed_targets,omitempty"`
	AllowedActions []string `json:"allowed_actions,omitempty"`
	CloudResources []string `json:"cloud_resources,omitempty"`
	ReviewRequired bool     `json:"review_required"`
}

func FromRuntime(agent runtime.AgentSummary, cloud []cloudaudit.Event) Draft {
	draft := Draft{SchemaVersion: "policy-draft.v1", AgentID: agent.AgentID, ReviewRequired: true}
	for _, environment := range agent.Environments {
		if strings.EqualFold(environment, "production") || strings.EqualFold(environment, "prod") {
			draft.Environment = "production"
			break
		}
		if draft.Environment == "" {
			draft.Environment = environment
		}
	}
	draft.AllowedTargets = append([]string(nil), agent.Targets...)
	for operation := range agent.Operations {
		draft.AllowedActions = append(draft.AllowedActions, operation)
	}
	for _, event := range cloud {
		if event.AgentID == agent.AgentID {
			draft.CloudResources = appendUnique(draft.CloudResources, event.Resource)
		}
	}
	sort.Strings(draft.AllowedTargets)
	sort.Strings(draft.AllowedActions)
	sort.Strings(draft.CloudResources)
	return draft
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}
