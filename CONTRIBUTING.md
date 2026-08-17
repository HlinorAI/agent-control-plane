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

The repository includes a fail-closed read-only hook. It checks staged paths and added diff lines for secret-like material, then runs the full local `agentctl` inventory gate. It never executes scanned content. Enable it for this checkout with:

```bash
mkdir -p .agentctl/bin
go build -trimpath -o .agentctl/bin/agentctl ./cmd/agentctl
git config core.hooksPath .githooks
```

The hook writes its SARIF report atomically with mode `0600` to the ignored `.agentctl/reports/` directory. It uses `.agentctl/bin/agentctl` when present, otherwise `agentctl` from `PATH`; set `AGENTCTL_BIN` to override the binary path. The staged guard blocks sensitive filenames, symlinks, unsafe paths, binary content that cannot be inspected locally, provider token patterns and high-entropy values near secret-like keys. It applies bounded Unicode/URL/escape normalization without executing content.

The hook verifies that the selected binary supports the expected `agentctl version` interface. Set `AGENTCTL_EXPECTED_VERSION` when a checkout requires an exact version pin.

Use `AGENTCTL_ALLOW_FAILURE=1 AGENTCTL_BYPASS_REASON='local emergency' git commit ...` only for an interactive local emergency. The bypass is rejected when `CI`, `GITHUB_ACTIONS`, `GITHUB_REF_PROTECTED`, `main` or `master` is detected. The reason is required but is not written to the repository or report.

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
