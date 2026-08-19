package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HlinorAI/agent-control-plane/internal/config"
	"github.com/HlinorAI/agent-control-plane/internal/scan"
)

var version = "dev"

const usage = `agentctl - read-only AI agent inventory and risk scanner

Usage:
  agentctl version
  agentctl init <path>
  agentctl scan <path> [flags]

Scan flags:
  --baseline file       suppress findings already present in a JSON report
  --config file         workspace policy file
  --debug               print safe discovery decisions to stderr
  --dry-run             list approved files without parsing content
  --fail-on severity    fail when findings meet severity: none, low, medium, high, critical
  --format format       output format: text, json or sarif
  --output file         write the report to a file instead of stdout
  --suppressions file   suppress active findings with reason and expiry from a JSON file

The scanner is read-only and metadata-only. It does not execute scanned content.
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "agentctl:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		if len(args) != 1 {
			return errors.New("help does not accept arguments")
		}
		_, err := io.WriteString(stdout, usage)
		return err
	}
	if args[0] == "version" || args[0] == "--version" || args[0] == "-v" {
		if len(args) != 1 {
			return errors.New("version does not accept arguments")
		}
		_, err := fmt.Fprintf(stdout, "agentctl %s\n", version)
		return err
	}
	if args[0] == "init" {
		return runInit(args[1:], stdout, stderr)
	}
	if args[0] != "scan" {
		return fmt.Errorf("unknown command %q; available commands are init and scan", args[0])
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		_, err := io.WriteString(stdout, usage)
		return err
	}
	if len(args) < 2 {
		return errors.New("scan requires a repository path")
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dryRun := fs.Bool("dry-run", false, "list approved files without parsing content")
	format := fs.String("format", "text", "output format: text, json or sarif")
	failOn := fs.String("fail-on", "none", "return a non-zero exit code at this severity or higher")
	output := fs.String("output", "", "write the report to a file instead of stdout")
	baseline := fs.String("baseline", "", "suppress findings already present in a JSON report")
	configFile := fs.String("config", "", "workspace policy file; defaults to <path>/.agentctl/config.yaml when present")
	debug := fs.Bool("debug", false, "print safe discovery decisions to stderr")
	suppressions := fs.String("suppressions", "", "suppress active findings with reason and expiry from a JSON file")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if *format != "text" && *format != "json" && *format != "sarif" {
		return fmt.Errorf("unsupported format %q", *format)
	}
	if !validSeverity(*failOn) {
		return fmt.Errorf("unsupported fail-on severity %q", *failOn)
	}

	root := args[1]
	policyPath, err := resolveConfigPath(root, *configFile)
	if err != nil {
		return err
	}
	suppressionPath := ""
	if *suppressions != "" {
		suppressionPath, err = resolveWorkspaceFile(root, *suppressions, "suppressions")
		if err != nil {
			return err
		}
	}
	options := scan.Options{DryRun: *dryRun, ConfigPath: policyPath, SuppressionPath: suppressionPath}
	if *debug {
		options.DebugWriter = stderr
	}
	report, err := scan.Run(root, options)
	if err != nil {
		return err
	}
	if *baseline != "" {
		if err := applyBaseline(&report, *baseline); err != nil {
			return err
		}
	}
	if *suppressions != "" {
		if err := applySuppressions(&report, suppressionPath, time.Now()); err != nil {
			return err
		}
	}

	if *output != "" {
		var payload []byte
		var err error
		switch *format {
		case "json":
			payload, err = json.MarshalIndent(report, "", "  ")
			if err == nil {
				payload = append(payload, '\n')
			}
		case "sarif":
			payload, err = report.SARIF()
			if err == nil {
				payload = append(payload, '\n')
			}
		default:
			payload = []byte(report.Text())
		}
		if err != nil {
			return err
		}
		if err := writeOutputFile(*output, payload); err != nil {
			return err
		}
	} else {
		writer := stdout

		var writeErr error
		switch *format {
		case "json":
			encoder := json.NewEncoder(writer)
			encoder.SetIndent("", "  ")
			writeErr = encoder.Encode(report)
		case "sarif":
			payload, err := report.SARIF()
			if err == nil {
				_, err = writer.Write(append(payload, '\n'))
			}
			writeErr = err
		default:
			_, writeErr = fmt.Fprint(writer, report.Text())
		}
		if writeErr != nil {
			return writeErr
		}
	}
	if findingsMeetThreshold(report.Findings, *failOn) {
		return fmt.Errorf("scan found findings at or above %s severity", *failOn)
	}
	return nil
}

func applyBaseline(report *scan.Report, path string) error {
	if report == nil {
		return errors.New("baseline requires a scan report")
	}
	baselinePath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve baseline path: %w", err)
	}
	file, err := os.Open(baselinePath)
	if err != nil {
		return fmt.Errorf("open baseline: %w", err)
	}
	defer file.Close()
	var baseline scan.Report
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&baseline); err != nil {
		return fmt.Errorf("decode baseline: %w", err)
	}
	if baseline.SchemaVersion == "" {
		return errors.New("baseline is not an agentctl JSON report")
	}
	known := make(map[string]struct{}, len(baseline.Findings))
	for _, finding := range baseline.Findings {
		if finding.ID != "" {
			known[finding.ID] = struct{}{}
		}
	}
	filtered := report.Findings[:0]
	for _, finding := range report.Findings {
		if _, exists := known[finding.ID]; exists {
			continue
		}
		filtered = append(filtered, finding)
	}
	report.Findings = filtered
	return nil
}

const maxSuppressionReasonLength = 500

type suppressionEntry struct {
	FindingID string `json:"finding_id"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
}

type suppressionDocument struct {
	Suppressions *[]suppressionEntry `json:"suppressions"`
}

func applySuppressions(report *scan.Report, path string, now time.Time) error {
	if report == nil {
		return errors.New("suppressions require a scan report")
	}
	suppressionPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve suppressions path: %w", err)
	}
	file, err := os.Open(suppressionPath)
	if err != nil {
		return fmt.Errorf("open suppressions: %w", err)
	}
	defer file.Close()

	var document suppressionDocument
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode suppressions: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("decode suppressions: multiple JSON values are not allowed")
		}
		return fmt.Errorf("decode suppressions: trailing data: %w", err)
	}
	if document.Suppressions == nil {
		return errors.New("suppression document must contain a suppressions array")
	}
	if len(*document.Suppressions) == 0 {
		return errors.New("suppression document must contain at least one suppression")
	}
	knownFindings := make(map[string]struct{}, len(report.Findings))
	for _, finding := range report.Findings {
		knownFindings[finding.ID] = struct{}{}
	}
	active := make(map[string]suppressionEntry, len(*document.Suppressions))
	for index, entry := range *document.Suppressions {
		id := strings.TrimSpace(entry.FindingID)
		reason := strings.TrimSpace(entry.Reason)
		if id == "" {
			return fmt.Errorf("suppression %d has no finding_id", index+1)
		}
		if reason == "" {
			return fmt.Errorf("suppression %q has no reason", id)
		}
		if len(reason) > maxSuppressionReasonLength {
			return fmt.Errorf("suppression %q reason exceeds %d characters", id, maxSuppressionReasonLength)
		}
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(entry.ExpiresAt))
		if err != nil {
			return fmt.Errorf("suppression %q has invalid expires_at: %w", id, err)
		}
		if !expiresAt.After(now) {
			return fmt.Errorf("suppression %q is expired", id)
		}
		if _, exists := knownFindings[id]; !exists {
			return fmt.Errorf("suppression %q does not match a finding in this scan", id)
		}
		if _, exists := active[id]; exists {
			return fmt.Errorf("duplicate suppression for %q", id)
		}
		entry.FindingID = id
		entry.Reason = reason
		entry.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
		active[id] = entry
	}
	for index := range report.Findings {
		if entry, exists := active[report.Findings[index].ID]; exists {
			report.Findings[index].Suppressed = true
			report.Findings[index].SuppressionReason = entry.Reason
			report.Findings[index].SuppressionExpiresAt = entry.ExpiresAt
		}
	}
	return nil
}

func validSeverity(value string) bool {
	switch value {
	case "none", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func findingsMeetThreshold(findings []scan.Finding, threshold string) bool {
	minimum := severityRank(threshold)
	if minimum == 0 {
		return false
	}
	for _, finding := range findings {
		if finding.Suppressed {
			continue
		}
		if severityRank(strings.ToLower(finding.Severity)) >= minimum {
			return true
		}
	}
	return false
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

func runInit(args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, err := io.WriteString(stdout, usage)
		return err
	}
	if len(args) < 1 {
		return errors.New("init requires a workspace path")
	}
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected init argument %q", fs.Arg(0))
	}
	root, err := filepath.Abs(args[0])
	if err != nil {
		return fmt.Errorf("resolve workspace path: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat workspace path: %w", err)
	}
	if !info.IsDir() {
		return errors.New("init workspace path must be a directory")
	}
	path := config.Path(root)
	if err := config.WriteDefault(path, config.Default(".")); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Initialized Agent Control Plane workspace\nConfig: %s\n", path)
	return err
}

func resolveConfigPath(root, requested string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve scan root: %w", err)
	}
	path := requested
	if path == "" {
		path = config.Path(absRoot)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve config path: %w", err)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("config must stay inside the scan root")
	}
	if _, err := os.Stat(absPath); err != nil {
		if errors.Is(err, os.ErrNotExist) && requested == "" {
			return "", nil
		}
		return "", fmt.Errorf("stat config: %w", err)
	}
	return absPath, nil
}

func resolveWorkspaceFile(root, requested, label string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve scan root: %w", err)
	}
	absPath, err := filepath.Abs(requested)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s must stay inside the scan root", label)
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s path must not be a symlink", label)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s path must be a regular file", label)
	}
	return absPath, nil
}

func writeOutputFile(path string, payload []byte) error {
	outputPath, err := resolveOutputPath(path)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(outputPath), ".agentctl-output-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary output: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(temporaryPath, outputPath); err != nil {
		return fmt.Errorf("replace output: %w", err)
	}
	removeTemporary = false
	return nil
}

func resolveOutputPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("output path must not be empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect output path: %w", err)
		}
	} else {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("output path must not be a symlink")
		}
		if !info.Mode().IsRegular() {
			return "", errors.New("output path must be a regular file")
		}
	}
	parent := filepath.Dir(abs)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("resolve output directory: %w", err)
	}
	parentInfo, err := os.Stat(resolvedParent)
	if err != nil {
		return "", fmt.Errorf("stat output directory: %w", err)
	}
	if !parentInfo.IsDir() {
		return "", errors.New("output parent must be a directory")
	}
	return filepath.Join(resolvedParent, filepath.Base(abs)), nil
}
