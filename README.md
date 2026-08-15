# Agent Control Plane

Read-only discovery and evidence-backed inventory for AI agents, tools, identities and MCP servers.

> Public alpha: the current scanner is a local, deterministic heuristic tool. It is useful for repository/configuration reviews, not a replacement for production security controls.

## Quick start

Run locally from a checkout:

```bash
go run ./cmd/agentctl version
go run ./cmd/agentctl init ./workspace
go run ./cmd/agentctl scan ./workspace --format text
go run ./cmd/agentctl scan ./workspace --format json --output report.json
go run ./cmd/agentctl scan ./workspace --format sarif --fail-on high --output agentctl.sarif
```

Install from the public module after the repository is released:

```bash
go install github.com/HlinorAI/agent-control-plane/cmd/agentctl@latest
agentctl version
agentctl scan . --format json --output report.json
```

Try the included risk fixture:

```bash
go run ./cmd/agentctl scan ./testdata/demo
```

The fixture intentionally produces three agents, one MCP server and findings across `ACP-001` through `ACP-010`.
The committed [sample SARIF report](testdata/demo/sample-report.sarif) shows the format without exposing secret values.

## What it does

The CLI scans an approved local directory in read-only mode and produces text or JSON inventory containing:

- likely agent entrypoints and declarative agent registry entries;
- model/provider references;
- tool and MCP references;
- identities, environments and ownership declarations;
- canonical relationships with source evidence;
- deterministic risk findings with file/line evidence;
- SARIF 2.1.0 output for GitHub Code Scanning and other security tooling;
- safe `.mcp.json` and `server.json` metadata such as server name, transport and auth method.

The default policy excludes common non-production paths such as tests, examples, samples, tutorials, fixtures, documentation, schemas and framework library layouts. Use `.agentctl/config.yaml` to add workspace-specific exclusions and approved providers or MCP servers. `agentctl init` never overwrites an existing policy.

## Risk rules

The alpha includes ten explainable rules:

| Rule | Detects |
|---|---|
| `ACP-001` | Missing agent owner/team |
| `ACP-002` | Runtime agent without source inventory |
| `ACP-003` | Shared identity across unrelated agents |
| `ACP-004` | Write/admin capability in a read-only use case |
| `ACP-005` | MCP server outside the approved registry |
| `ACP-006` | Production credential referenced in development |
| `ACP-007` | Sensitive tool without approval metadata |
| `ACP-008` | Provider/model outside workspace policy |
| `ACP-009` | Missing production disable/rollback path |
| `ACP-010` | Stale agent verification metadata |

## Security boundary

- read-only by default;
- no arbitrary code execution;
- repository contents are treated as untrusted data;
- no raw secret values or full production payloads in reports;
- metadata-only output and source locators;
- no network calls in the local scan path;
- deterministic findings; no LLM in the critical risk-decision path;
- bounded file size, file count and total scan input.

## Current limitations

- Detection is heuristic and should be reviewed by a human.
- The alpha scans local repositories and configuration files; GitHub, GitLab, Docker and Kubernetes connectors are not implemented yet.
- No runtime proxy, IAM remediation, hosted control plane, dashboard or compliance certification is included.
- JSON and SARIF are the stable report formats for the current slice; CSV and issue export are planned.

SARIF is available now. Use `--fail-on high` or `--fail-on critical` to make findings a CI gate; the default `none` keeps scans informational.

### GitHub Actions example

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-go@v5
  with:
    go-version-file: go.mod
- run: go run ./cmd/agentctl scan . --format sarif --fail-on high --output agentctl.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: agentctl.sarif
```

## Development

Requirements: Go 1.26 or newer.

```bash
go test ./...
go vet ./...
go build ./cmd/agentctl
```

The repository uses GitHub Actions for these checks and GoReleaser for tagged alpha binaries.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
