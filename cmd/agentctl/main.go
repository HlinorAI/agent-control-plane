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

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "agentctl:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agentctl init <path> | agentctl scan <path> [--config file] [--dry-run] [--format text|json] [--output file]")
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
	format := fs.String("format", "text", "output format: text or json")
	output := fs.String("output", "", "write the report to a file instead of stdout")
	configFile := fs.String("config", "", "workspace policy file; defaults to <path>/.agentctl/config.yaml when present")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("unsupported format %q", *format)
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

	if *format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}

	_, err = fmt.Fprint(writer, report.Text())
	return err
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
