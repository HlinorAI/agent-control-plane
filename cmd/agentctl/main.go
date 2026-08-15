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

	"github.com/HlinorAI/agent-control-plane/internal/config"
	"github.com/HlinorAI/agent-control-plane/internal/scan"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "agentctl:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agentctl version | agentctl init <path> | agentctl scan <path> [--config file] [--dry-run] [--format text|json|sarif] [--fail-on none|low|medium|high|critical] [--output file]")
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
	if len(args) < 2 {
		return errors.New("scan requires a repository path")
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dryRun := fs.Bool("dry-run", false, "list approved files without parsing content")
	format := fs.String("format", "text", "output format: text, json or sarif")
	failOn := fs.String("fail-on", "none", "return a non-zero exit code at this severity or higher")
	output := fs.String("output", "", "write the report to a file instead of stdout")
	configFile := fs.String("config", "", "workspace policy file; defaults to <path>/.agentctl/config.yaml when present")
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
	report, err := scan.Run(root, scan.Options{DryRun: *dryRun, ConfigPath: policyPath})
	if err != nil {
		return err
	}

	var writer io.Writer = stdout
	if *output != "" {
		if err := ensureOutputInsideCurrentDirectory(*output); err != nil {
			return err
		}
		file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer file.Close()
		writer = file
	}

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
	if findingsMeetThreshold(report.Findings, *failOn) {
		return fmt.Errorf("scan found findings at or above %s severity", *failOn)
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

func ensureOutputInsideCurrentDirectory(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return errors.New("output must stay inside the current working directory")
	}
	return nil
}
