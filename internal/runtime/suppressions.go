package runtime

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

type suppressionEntry struct {
	FindingID string `json:"finding_id"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
}
type suppressionDocument struct {
	Suppressions *[]suppressionEntry `json:"suppressions"`
}

func ApplyBaseline(report *AuditReport, baseline io.Reader) error {
	if report == nil {
		return fmt.Errorf("baseline requires a runtime audit report")
	}
	var previous AuditReport
	decoder := json.NewDecoder(baseline)
	if err := decoder.Decode(&previous); err != nil {
		return fmt.Errorf("decode runtime baseline: %w", err)
	}
	if previous.SchemaVersion == "" {
		return fmt.Errorf("baseline is not a runtime audit report")
	}
	known := make(map[string]bool, len(previous.Findings))
	for _, finding := range previous.Findings {
		if finding.ID != "" {
			known[finding.ID] = true
		}
	}
	filtered := report.Findings[:0]
	for _, finding := range report.Findings {
		if !known[finding.ID] {
			filtered = append(filtered, finding)
		}
	}
	report.Findings = filtered
	return nil
}

func ApplySuppressions(report *AuditReport, source io.Reader, now time.Time) error {
	if report == nil {
		return fmt.Errorf("suppressions require a runtime audit report")
	}
	var document suppressionDocument
	decoder := json.NewDecoder(source)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode runtime suppressions: %w", err)
	}
	if document.Suppressions == nil || len(*document.Suppressions) == 0 {
		return fmt.Errorf("runtime suppression document must contain at least one suppression")
	}
	known := make(map[string]bool, len(report.Findings))
	for _, finding := range report.Findings {
		known[finding.ID] = true
	}
	active := make(map[string]suppressionEntry, len(*document.Suppressions))
	for index, entry := range *document.Suppressions {
		entry.FindingID = strings.TrimSpace(entry.FindingID)
		entry.Reason = strings.TrimSpace(entry.Reason)
		if entry.FindingID == "" || entry.Reason == "" {
			return fmt.Errorf("runtime suppression %d requires finding_id and reason", index+1)
		}
		if len(entry.Reason) > 500 {
			return fmt.Errorf("runtime suppression %q reason exceeds 500 characters", entry.FindingID)
		}
		expires, err := time.Parse(time.RFC3339, strings.TrimSpace(entry.ExpiresAt))
		if err != nil || !expires.After(now) {
			return fmt.Errorf("runtime suppression %q has invalid or expired expires_at", entry.FindingID)
		}
		if !known[entry.FindingID] {
			return fmt.Errorf("runtime suppression %q does not match a finding", entry.FindingID)
		}
		if _, exists := active[entry.FindingID]; exists {
			return fmt.Errorf("duplicate runtime suppression for %q", entry.FindingID)
		}
		entry.ExpiresAt = expires.UTC().Format(time.RFC3339)
		active[entry.FindingID] = entry
	}
	for index := range report.Findings {
		if entry, ok := active[report.Findings[index].ID]; ok {
			report.Findings[index].Suppressed = true
			report.Findings[index].SuppressionReason = entry.Reason
			report.Findings[index].SuppressionExpiresAt = entry.ExpiresAt
		}
	}
	return nil
}
