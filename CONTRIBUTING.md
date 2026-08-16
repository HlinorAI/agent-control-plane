# Contributing

Contributions are welcome during the public alpha.

## Before opening a pull request

Run:

```bash
gofmt -w .
go test ./...
go vet ./...
go build ./cmd/agentctl
```

For scanner changes, also run the demo scan and verify both text and SARIF output:

```bash
go run ./cmd/agentctl scan ./testdata/demo --format text
go run ./cmd/agentctl scan ./testdata/demo --format sarif --output /tmp/agentctl.sarif
```

## Optional local pre-commit scan

The repository includes a lightweight read-only hook. It blocks only High/Critical findings and never executes scanned content. Enable it for this checkout with:

```bash
mkdir -p .agentctl/bin
go build -trimpath -o .agentctl/bin/agentctl ./cmd/agentctl
git config core.hooksPath .githooks
```

The hook writes its SARIF report to the ignored `.agentctl/reports/` directory. It uses `.agentctl/bin/agentctl` when present, otherwise `agentctl` from `PATH`; set `AGENTCTL_BIN` to override the binary path. Use `AGENTCTL_ALLOW_FAILURE=1 git commit ...` only for a local emergency bypass. The bypass is rejected when `CI` is enabled.

Copy [.agentctl/config.example.yaml](.agentctl/config.example.yaml) to `.agentctl/config.yaml` when a workspace needs explicit exclusions, approved providers, approved MCP servers or freshness policy. Keep credentials, tokens, private URLs and raw payloads out of the policy file.

## Scanner changes

- Keep discovery read-only and metadata-only.
- Never execute scanned code or repository hooks.
- Never emit secret values or full payloads.
- Add a regression test for every new heuristic or path filter.
- Prefer deterministic, explainable findings with file/line evidence.
- Keep framework and sample fixtures separate from production-like fixtures.

## Pull requests

Describe the behavior change, evidence used to validate it and any false-positive or false-negative tradeoff. Keep changes focused and do not include generated binaries, local reports, credentials or unrelated formatting.
