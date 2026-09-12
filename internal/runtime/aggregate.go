package runtime

import (
	"sort"
	"strings"
)

func Aggregate(events []Event, skipped int) Report {
	state := newAggregateState()
	for _, event := range events {
		state.add(event)
	}
	report := state.report()
	report.EventsSkipped = skipped
	return report
}

func addEvent(summary *AgentSummary, event Event) {
	summary.EventCount++
	if event.Success {
		summary.SuccessfulEvents++
	} else {
		summary.FailedEvents++
	}
	if isWriteAction(event.Action) {
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

func normalizeSummary(summary *AgentSummary) {
	sort.Strings(summary.Targets)
	sort.Strings(summary.Environments)
	sort.Strings(summary.Providers)
}

func sortSummaries(agents []AgentSummary) {
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
}

func isWriteAction(action string) bool {
	return strings.EqualFold(action, "write") || strings.EqualFold(action, "delete") || strings.EqualFold(action, "mutate")
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
