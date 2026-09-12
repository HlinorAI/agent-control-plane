package runtime

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
)

type Diff struct {
	SchemaVersion string    `json:"schema_version"`
	Added         []Finding `json:"added_findings"`
	Removed       []Finding `json:"removed_findings"`
	Unchanged     int       `json:"unchanged_findings"`
}

func DiffReports(before, after AuditReport) Diff {
	old := make(map[string]Finding, len(before.Findings))
	for _, f := range before.Findings {
		old[f.ID] = f
	}
	current := make(map[string]Finding, len(after.Findings))
	for _, f := range after.Findings {
		current[f.ID] = f
	}
	result := Diff{SchemaVersion: "runtime-diff.v1"}
	for id, finding := range current {
		if _, ok := old[id]; ok {
			result.Unchanged++
		} else {
			result.Added = append(result.Added, finding)
		}
	}
	for id, finding := range old {
		if _, ok := current[id]; !ok {
			result.Removed = append(result.Removed, finding)
		}
	}
	sort.Slice(result.Added, func(i, j int) bool { return result.Added[i].ID < result.Added[j].ID })
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i].ID < result.Removed[j].ID })
	return result
}

func (d Diff) CSV() ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"change", "finding_id", "rule_id", "severity", "agent_id", "message"}); err != nil {
		return nil, err
	}
	write := func(change string, findings []Finding) error {
		for _, f := range findings {
			if err := writer.Write([]string{change, f.ID, f.RuleID, f.Severity, f.AgentID, f.Message}); err != nil {
				return err
			}
		}
		return nil
	}
	if err := write("added", d.Added); err != nil {
		return nil, err
	}
	if err := write("removed", d.Removed); err != nil {
		return nil, err
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

func (d Diff) HTML() ([]byte, error) {
	const page = `<!doctype html><meta charset="utf-8"><title>Agent Control Plane Runtime Diff</title><style>body{font:15px system-ui;margin:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:.5rem;text-align:left}.added{color:#087f23}.removed{color:#b42318}</style><h1>Runtime audit diff</h1><p>Added: {{len .Added}} · Removed: {{len .Removed}} · Unchanged: {{.Unchanged}}</p><table><tr><th>Change</th><th>ID</th><th>Rule</th><th>Severity</th><th>Agent</th><th>Message</th></tr>{{range .Added}}<tr class="added"><td>Added</td><td>{{.ID}}</td><td>{{.RuleID}}</td><td>{{.Severity}}</td><td>{{.AgentID}}</td><td>{{.Message}}</td></tr>{{end}}{{range .Removed}}<tr class="removed"><td>Removed</td><td>{{.ID}}</td><td>{{.RuleID}}</td><td>{{.Severity}}</td><td>{{.AgentID}}</td><td>{{.Message}}</td></tr>{{end}}</table>`
	t, err := template.New("diff").Parse(page)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if err := t.Execute(&buffer, d); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func ReadAuditReport(path string) (AuditReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return AuditReport{}, fmt.Errorf("read runtime report: %w", err)
	}
	var report AuditReport
	if err := json.Unmarshal(data, &report); err != nil {
		return AuditReport{}, fmt.Errorf("decode runtime report: %w", err)
	}
	if report.SchemaVersion == "" {
		return AuditReport{}, fmt.Errorf("runtime report schema_version is required")
	}
	return report, nil
}
