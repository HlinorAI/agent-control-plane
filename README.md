# Agent Control Plane

Read-only discovery and evidence-backed inventory for internal AI agents.

## P0 CLI

The first slice is a local Go CLI. It reads approved text/configuration files, never executes repository contents, never sends data over the network, and emits only metadata and source locators.

```bash
go run ./cmd/agentctl init .
go run ./cmd/agentctl scan . --dry-run
go run ./cmd/agentctl scan . --format json
```

`agentctl init` creates `.agentctl/config.yaml` with workspace policy, exclusions and a 30-day verification freshness TTL. Existing configuration is never overwritten. `agentctl scan` loads this file automatically when it exists; use `--config` to select another policy file inside the scan root.

The scanner detects likely agent/model/tool references, canonical relationships and explainable `ACP-001`–`ACP-010` findings. It filters common non-production paths such as tests, examples, fixtures and schemas, and keeps runtime code separate from JSON/YAML/TOML runtime metadata. It is intentionally heuristic and does not claim production status without source evidence. The MCP collector reads safe server/manifest metadata, including server name, transport and auth method, without reading secret values or payloads.

## Security boundary

- read-only by default;
- no arbitrary code execution;
- no raw secrets or full payloads in reports;
- metadata-only output;
- deterministic findings with file/line evidence;
- no network calls in the local P0 path.

Local planning, market research, roadmap, architecture and security preparation files are intentionally ignored by GitHub. The repository contains the working CLI, tests, fixtures and runtime configuration.
