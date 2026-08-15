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

## Scanner changes

- Keep discovery read-only and metadata-only.
- Never execute scanned code or repository hooks.
- Never emit secret values or full payloads.
- Add a regression test for every new heuristic or path filter.
- Prefer deterministic, explainable findings with file/line evidence.
- Keep framework and sample fixtures separate from production-like fixtures.

## Pull requests

Describe the behavior change, evidence used to validate it and any false-positive or false-negative tradeoff. Keep changes focused and do not include generated binaries, local reports, credentials or unrelated formatting.
