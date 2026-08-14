# Agent Control Plane

Read-only discovery and evidence-backed inventory for internal AI agents.

## P0 CLI

The first slice is a local Go CLI. It reads approved text/configuration files, never executes repository contents, never sends data over the network, and emits only metadata and source locators.

```bash
go run ./cmd/agentctl scan . --dry-run
go run ./cmd/agentctl scan . --format json
```

The scanner currently detects likely agent/model/tool references and reports `ACP-001` owner-gap findings. It is intentionally heuristic and does not claim production status without source evidence.

## Security boundary

- read-only by default;
- no arbitrary code execution;
- no raw secrets or full payloads in reports;
- metadata-only output;
- deterministic findings with file/line evidence;
- no network calls in the local P0 path.

See [PROJECT_PLAN.md](PROJECT_PLAN.md), [TODO.md](TODO.md), [Архитектура MVP Agent Control Plane.txt](Архитектура%20MVP%20Agent%20Control%20Plane.txt) and [Security & Compliance Blueprint для Agent Control Plane.md](Security%20%26%20Compliance%20Blueprint%20для%20Agent%20Control%20Plane.md).

