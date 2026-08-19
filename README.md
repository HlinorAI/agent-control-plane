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

For incremental CI gates, keep a reviewed JSON report and suppress findings that
were already accepted in that baseline:

```bash
go run ./cmd/agentctl scan ./workspace --format json --output baseline.json
go run ./cmd/agentctl scan ./workspace --format sarif --baseline baseline.json --fail-on high --output agentctl.sarif
```

The baseline matches stable finding IDs. It does not weaken the scanner rules;
it only removes findings already present in the supplied report from the current
output. Review and update the baseline deliberately.

For a time-bound exception, use a separate suppression document. Every entry
requires a stable finding ID, a reviewable reason, and an RFC 3339 expiry:

```bash
go run ./cmd/agentctl scan ./workspace --format sarif \
  --suppressions .agentctl/suppressions.json --fail-on high --output agentctl.sarif
```

Example document:

```json
{
  "suppressions": [
    {
      "finding_id": "finding_0123456789abcdef",
      "reason": "Accepted until the permission migration is complete",
      "expires_at": "2026-12-31T23:59:59Z"
    }
  ]
}
```

Suppressed findings remain visible in JSON, text, and SARIF with their reason
and expiry; they are excluded from `--fail-on`. SARIF uses the standard
`result.suppressions` field with `kind: external`. Unknown finding IDs,
unknown JSON fields, a misspelled top-level key, expired, duplicate, or
incomplete entries fail closed. Finding IDs are deterministic opaque IDs tied
to the source path/entity and rule, so renaming a source file or changing the
rule context requires reviewing the suppression again. Use `--debug` to print
safe discovery decisions to stderr while keeping JSON and SARIF on stdout or
the selected output path.

Output paths may be relative or absolute. The parent directory must already
exist, output directories are rejected, final output symlinks are rejected, and
reports are written atomically with mode `0600`.

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

Run the manifest-driven adversarial corpus:

```bash
go test ./internal/adversarial -run TestAdversarialCorpus -count=1 -v
go test ./internal/adversarial -count=1 -v
go test ./internal/runtimefuzz -fuzz '^FuzzToolCallArguments$' -fuzztime=2s -count=1
go test ./internal/runtimefuzz -fuzz '^FuzzMCPMetadata$' -fuzztime=2s -count=1
go run ./cmd/fuzzpayloadcheck -root internal/runtimefuzz/testdata/fuzz -max-bytes 262144 -allow-adversarial > fuzz-payload-validation.json
```

The corpus uses synthetic fixtures and checks structured JSON/SARIF/text output, deterministic results, secret non-disclosure, inert command handling, network isolation, root containment, malformed input handling, and CLI severity exit codes.

The runtime fuzz targets are standalone safe parser seams. They classify in-memory tool-call and MCP metadata only; they do not dispatch tools, start processes, read files, install packages, resolve credentials, or contact URLs. The file-backed seed corpus and manifest live under `internal/runtimefuzz/testdata/fuzz/`; the separate `.github/workflows/adversarial-fuzz.yml` workflow runs matrix smoke/nightly checks, while tagged releases repeat the fuzz gates before GoReleaser.

`fuzzpayloadcheck` runs in strict mode by default. The `-allow-adversarial` option is only for the committed negative-case corpus: it permits expected malformed, duplicate-key, unsafe-URL, control-character, and inert command fixtures while keeping credential-like values, invalid UTF-8, resource-limit violations, unsafe paths, and filesystem errors blocking.

Run the pinned external-repository precision benchmark locally after cloning the
repositories listed in `testdata/benchmark/manifest.json`:

```bash
go run ./cmd/agentctl-benchmark --root /path/to/benchmark-root
```

The benchmark is a regression gate for candidate count, non-policy ACP-005
findings and code-like metadata values. It reports only aggregate counts; it
does not print source values. The weekly and manually triggered workflow
`.github/workflows/external-benchmark.yml` checks out the exact manifest refs
before running the gate. Thresholds are reviewed baselines, not a claim of
ground-truth precision or recall.

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

ACP-005 is emitted only for MCP policy sources such as `.mcp.json`,
`server.json`, and explicitly named MCP/server/manifest JSON or YAML files.
Source-code references to an MCP server are inventory evidence but do not create
a policy finding by themselves.

The default policy excludes common non-production paths such as tests, examples, samples, tutorials, fixtures, documentation and schemas. Agent definitions under tooling directories such as `.claude` and `.github`, Markdown agent files, and framework library layouts remain scannable when they contain strong agent signals. Use `.agentctl/config.yaml` to add workspace-specific exclusions and approved providers or MCP servers. `agentctl init` never overwrites an existing policy.

## Risk rules

The alpha includes ten explainable rules:

| Rule | Detects |
|---|---|
| `ACP-001` | Missing agent owner/team (informational unless production is explicit) |
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
- local pre-commit protection checks staged diff additions, sensitive filenames, symlinks and secret-like patterns; CI remains authoritative for full history and artifact checks.

## Current limitations

- Detection is heuristic and should be reviewed by a human.
- The alpha scans local repositories and configuration files; GitHub, GitLab, Docker and Kubernetes connectors are not implemented yet.
- No runtime proxy, IAM remediation, hosted control plane, dashboard or compliance certification is included.
- JSON and SARIF are the stable report formats for the current slice; CSV and issue export are planned.

SARIF is available now. Use `--fail-on high` or `--fail-on critical` to make findings a CI gate; the default `none` keeps scans informational.
Use `agentctl --help`, `agentctl scan --help`, or `agentctl init --help` for the supported command surface.

### GitHub Actions example

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-go@v5
  with:
    go-version-file: go.mod
- run: go run ./cmd/agentctl scan . --format sarif --fail-on high --output agentctl.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: agentctl.sarif
```

Pull requests in this repository also run `.github/workflows/agentctl-pr.yml`, which builds the local CLI, uploads SARIF to GitHub Code Scanning, and blocks High/Critical findings through the CLI exit code.

## Development

Requirements: Go 1.26 or newer.

```bash
go test ./...
go vet ./...
go build ./cmd/agentctl
```

The repository uses GitHub Actions for these checks and GoReleaser for tagged alpha binaries.

Suspicious fuzz payloads are treated as untrusted artifacts. See the [security policy](SECURITY.md) and the [quarantine record template](security/quarantine-record.example.json) before handling a validator rejection.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
