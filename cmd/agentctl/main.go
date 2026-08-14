package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hlinor-systems/agent-control-plane/internal/scan"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "agentctl:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agentctl scan <path> [--dry-run] [--format text|json] [--output file]")
	}
	if args[0] != "scan" {
		return fmt.Errorf("unknown command %q; only scan is available in P0", args[0])
	}
	if len(args) < 2 {
		return errors.New("scan requires a repository path")
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dryRun := fs.Bool("dry-run", false, "list approved files without parsing content")
	format := fs.String("format", "text", "output format: text or json")
	output := fs.String("output", "", "write the report to a file instead of stdout")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("unsupported format %q", *format)
	}

	report, err := scan.Run(fs.Arg(0), scan.Options{DryRun: *dryRun})
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
