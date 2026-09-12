package runtime

import (
	"sort"
	"strings"
)

func Aggregate(events []Event, skipped int) Report {
	byKey := make(map[string]*AgentSummary)
	for _, event := range events {
		key := event.AgentID
		if key == "" {
			key = "name:" + event.AgentName
		}
		summary := byKey[key]
		if summary == nil {
			summary = &AgentSummary{
				AgentID:    event.AgentID,
				AgentName:  event.AgentName,
				FirstSeen:  event.Timestamp,
				LastSeen:   event.Timestamp,
				Operations: make(map[string]int),
			}
			byKey[key] = summary
		}
		summary.EventCount++
		if event.Success {
			summary.SuccessfulEvents++
		} else {
			summary.FailedEvents++
		}
		if strings.EqualFold(event.Action, "write") || strings.EqualFold(event.Action, "delete") || strings.EqualFold(event.Action, "mutate") {
			summary.WriteEvents++
		}
		if event.Timestamp.Before(summary.FirstSeen) {
			summary.FirstSeen = event.Timestamp
		}
		if event.Timestamp.After(summary.LastSeen) {
			summary.LastSeen = event.Timestamp
		}
		summary.Targets = appendUnique(summary.Targets, event.Target)
		summary.Environments = appendUnique(summary.Environments, event.Environment)
		summary.Providers = appendUnique(summary.Providers, event.Provider)
		summary.Operations[event.Operation]++
	}

	agents := make([]AgentSummary, 0, len(byKey))
	for _, summary := range byKey {
		sort.Strings(summary.Targets)
		sort.Strings(summary.Environments)
		sort.Strings(summary.Providers)
		agents = append(agents, *summary)
	}
	sort.Slice(agents, func(i, j int) bool {
		left := agents[i].AgentID
		if left == "" {
			left = "name:" + agents[i].AgentName
		}
		right := agents[j].AgentID
		if right == "" {
			right = "name:" + agents[j].AgentName
		}
		return left < right
	})
	return Report{SchemaVersion: "runtime.v1", EventsRead: len(events), EventsSkipped: skipped, Agents: agents}
}

func appendUnique(values []string, value string) []string {
	if strings.TrimSpace(value) == "" {
		return values
	}
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}
