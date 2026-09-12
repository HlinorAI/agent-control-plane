package runtime

import "time"

const (
	DefaultMaxLineBytes = 1 << 20
	DefaultMaxEvents    = 1_000_000
)

type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	RequestID   string    `json:"request_id,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
	AgentName   string    `json:"agent_name,omitempty"`
	Environment string    `json:"environment,omitempty"`
	Operation   string    `json:"operation"`
	Target      string    `json:"target"`
	Provider    string    `json:"provider,omitempty"`
	Action      string    `json:"action,omitempty"`
	Success     bool      `json:"success"`
}

type AgentSummary struct {
	AgentID          string         `json:"agent_id,omitempty"`
	AgentName        string         `json:"agent_name,omitempty"`
	EventCount       int            `json:"event_count"`
	SuccessfulEvents int            `json:"successful_events"`
	FailedEvents     int            `json:"failed_events"`
	WriteEvents      int            `json:"write_events"`
	FirstSeen        time.Time      `json:"first_seen"`
	LastSeen         time.Time      `json:"last_seen"`
	Targets          []string       `json:"targets,omitempty"`
	Environments     []string       `json:"environments,omitempty"`
	Operations       map[string]int `json:"operations,omitempty"`
	Providers        []string       `json:"providers,omitempty"`
}

type Report struct {
	SchemaVersion string         `json:"schema_version"`
	EventsRead    int            `json:"events_read"`
	EventsSkipped int            `json:"events_skipped"`
	Agents        []AgentSummary `json:"agents"`
}
