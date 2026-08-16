package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const FileName = ".agentctl/config.yaml"

type Config struct {
	Version            string
	WorkspaceRoot      string
	FreshnessDays      int
	Exclude            []string
	ApprovedOwners     []string
	ApprovedProviders  []string
	ApprovedMCPServers []string
}

func Default(workspaceRoot string) Config {
	return Config{
		Version:            "1",
		WorkspaceRoot:      workspaceRoot,
		FreshnessDays:      30,
		Exclude:            []string{".agentctl", ".git", ".hg", ".svn", ".storybook", "__tests__", "e2e", "test-servers", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__", "examples", "example", "samples", "sample", "demos", "demo", "tutorials", "tutorial", "docs_src", "tests", "test", "testdata", "fixtures", "benchmarks", "docs", "doc", "schemas", "schema"},
		ApprovedOwners:     []string{},
		ApprovedProviders:  []string{},
		ApprovedMCPServers: []string{},
	}
}

func Path(root string) string {
	return filepath.Join(root, FileName)
}

func WriteDefault(path string, cfg Config) error {
	if cfg.Version == "" {
		cfg.Version = "1"
	}
	if cfg.WorkspaceRoot == "" {
		cfg.WorkspaceRoot = "."
	}
	if cfg.FreshnessDays <= 0 {
		cfg.FreshnessDays = 30
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	defer file.Close()
	if _, err := file.WriteString(render(cfg)); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	return nil
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	cfg := Default(".")
	listKey := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			if listKey == "" {
				return Config{}, errors.New("list item appears before a list key")
			}
			value := cleanValue(strings.TrimSpace(strings.TrimPrefix(line, "-")))
			if value != "" {
				appendListValue(&cfg, listKey, value)
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return Config{}, fmt.Errorf("invalid config line %q", line)
		}
		key := normalizeKey(parts[0])
		value := cleanValue(parts[1])
		listKey = ""
		switch key {
		case "version":
			cfg.Version = value
		case "workspace_root":
			cfg.WorkspaceRoot = value
		case "freshness_days":
			days, err := strconv.Atoi(value)
			if err != nil || days <= 0 {
				return Config{}, fmt.Errorf("freshness_days must be a positive integer")
			}
			cfg.FreshnessDays = days
		case "exclude", "approved_owners", "approved_providers", "approved_mcp_servers":
			listKey = key
			if value != "" && value != "[]" {
				appendListValue(&cfg, key, value)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if cfg.Version == "" {
		return Config{}, errors.New("config version is required")
	}
	return cfg, nil
}

func render(cfg Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "version: %s\nworkspace_root: %s\nfreshness_days: %d\n\n", quote(cfg.Version), quote(cfg.WorkspaceRoot), cfg.FreshnessDays)
	writeList(&b, "exclude", cfg.Exclude)
	writeList(&b, "approved_owners", cfg.ApprovedOwners)
	writeList(&b, "approved_providers", cfg.ApprovedProviders)
	writeList(&b, "approved_mcp_servers", cfg.ApprovedMCPServers)
	return b.String()
}

func writeList(b *strings.Builder, key string, values []string) {
	if len(values) == 0 {
		fmt.Fprintf(b, "%s: []\n\n", key)
		return
	}
	fmt.Fprintf(b, "%s:\n", key)
	for _, value := range values {
		fmt.Fprintf(b, "  - %s\n", quote(value))
	}
	b.WriteByte('\n')
}

func appendListValue(cfg *Config, key, value string) {
	switch key {
	case "exclude":
		cfg.Exclude = appendUnique(cfg.Exclude, value)
	case "approved_owners":
		cfg.ApprovedOwners = appendUnique(cfg.ApprovedOwners, value)
	case "approved_providers":
		cfg.ApprovedProviders = appendUnique(cfg.ApprovedProviders, value)
	case "approved_mcp_servers":
		cfg.ApprovedMCPServers = appendUnique(cfg.ApprovedMCPServers, value)
	}
}

func appendUnique(values []string, value string) []string {
	for _, current := range values {
		if strings.EqualFold(current, value) {
			return values
		}
	}
	return append(values, value)
}

func normalizeKey(value string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
}

func cleanValue(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.Index(value, " #"); index >= 0 {
		value = strings.TrimSpace(value[:index])
	}
	return strings.Trim(value, "\"'")
}

func quote(value string) string {
	return strconv.Quote(value)
}
