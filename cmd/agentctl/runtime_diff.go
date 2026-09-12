package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/HlinorAI/agent-control-plane/internal/runtime"
)

func runRuntimeDiff(args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("runtime-diff requires before and after runtime JSON reports")
	}
	fs := flag.NewFlagSet("runtime-diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text, json, csv or html")
	output := fs.String("output", "", "write the diff to a file instead of stdout")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if *format != "text" && *format != "json" && *format != "csv" && *format != "html" {
		return fmt.Errorf("unsupported runtime diff format %q", *format)
	}
	before, err := runtime.ReadAuditReport(args[0])
	if err != nil {
		return err
	}
	after, err := runtime.ReadAuditReport(args[1])
	if err != nil {
		return err
	}
	diff := runtime.DiffReports(before, after)
	var payload []byte
	switch *format {
	case "json":
		payload, err = json.MarshalIndent(diff, "", "  ")
		if err == nil {
			payload = append(payload, '\n')
		}
	case "csv":
		payload, err = diff.CSV()
	case "html":
		payload, err = diff.HTML()
	default:
		payload = []byte(fmt.Sprintf("Runtime diff\nAdded findings: %d\nRemoved findings: %d\nUnchanged findings: %d\n", len(diff.Added), len(diff.Removed), diff.Unchanged))
	}
	if err != nil {
		return err
	}
	if *output != "" {
		return writeOutputFile(*output, payload)
	}
	_, err = stdout.Write(payload)
	return err
}
