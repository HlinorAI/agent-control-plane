# Agent Control Plane Runtime Audit: MVP

## Decision

Agent Control Plane should be extended with a separate **runtime evidence layer**, not turned from a static scanner into a proxy or an execution system. The static scanner answers "what is declared in the code"; the runtime audit answers "what actually happened". These results must be linked by a stable agent identifier and merged only at the reporting stage.

The MVP must accept normalized events in JSON Lines format, aggregate actual calls and match them against the static scan result. At this stage the system must not execute tools, intercept secrets, change policies or require a specific observability provider.

## Goals and limits

| Area | In MVP | Not in MVP |
|---|---|---|
| Sources | Normalized JSONL, API Gateway JSON/JSONL, OpenTelemetry JSON export | Direct integration with every vendor |
| Format | JSONL with a normalized event | Ad-hoc parsing of each product's logs |
| Analytics | Call counts, success rate, unique targets, first/last seen | Behavioral ML detection |
| Matching | `agent_id`, then stable name with an explicit warning | Ambiguous automatic linking without evidence |
| Security | Metadata-only, size limits, no payload/arguments | Collecting prompts, tool arguments and raw secrets |
| Output | JSON report and runtime findings | Enforcement and runtime proxy |

## Normalized event

Each input line represents one event. Request and response payloads are intentionally absent. Identifiers and names are limited to the metadata required for audit.

```json
{
  "timestamp": "2026-09-12T12:00:00Z",
  "request_id": "req-123",
  "agent_id": "agent_customer_support",
  "agent_name": "customer-support",
  "environment": "production",
  "operation": "tool_call",
  "target": "crm.search_customers",
  "provider": "internal-crm",
  "action": "read",
  "success": true
}
```

Required fields: `timestamp`, `agent_id` or `agent_name`, `operation`, `target`, `success`. The formal schema is published in [`docs/runtime-event.v1.schema.json`](./runtime-event.v1.schema.json). The `operation` and `action` values are free-form strings at the MVP stage so integrations are not blocked. The normalizer must reject empty identifiers and invalid timestamps.

## Runtime aggregate

The following metrics are aggregated per agent:

| Metric | Purpose |
|---|---|
| `event_count` | Total observation volume |
| `successful_events` and `failed_events` | Reliability and integration errors |
| `unique_targets` | Actual tool and API scope |
| `operations` | Breakdown by operation type |
| `providers` | Actual model/API providers |
| `first_seen` and `last_seen` | Observation window |
| `undeclared_targets` | Targets missing from the static inventory |
| `undeclared_providers` | Providers missing from the declaration |

Aggregates are sorted deterministically. This is required for stable diff reports and for the baseline mechanism already used by the static scanner. The JSONL source is aggregated as a stream and does not hold the full event list in memory. For the OpenTelemetry and API Gateway envelope formats, safe normalization runs first, then the same aggregate model is applied.

## Runtime findings

The first rule set must be small and verifiable:

| Rule | Condition | Initial severity |
|---|---|---|
| `ACP-R001` | Actual target is missing from the agent's static inventory | High |
| `ACP-R002` | Actual provider differs from the declared one | High |
| `ACP-R003` | A production agent calls a target with a write action while declared read-only | Critical |
| `ACP-R004` | Runtime events cannot be reliably matched to an agent | Medium |
| `ACP-R005` | Observed events are older than the configured freshness window | Note |

Rules must build evidence only from safe fields: `request_id`, timestamp, operation and target. A finding must never contain a prompt, tool arguments, authorization headers or a response body.

## Implementation plan

1. **Ingest layer.** Add a streaming JSONL reader with a line-size limit and a total-event limit.
2. **Aggregation.** Add a deterministic runtime report with first/last seen and unique targets.
3. **Matching.** Match the runtime agent to `scan.Report.Agents`; when `agent_id` is absent, allow a name match only when it is unambiguous.
4. **Findings.** Add the first runtime rules without enforcement.
5. **CLI.** Add a separate `agentctl runtime-audit <events.jsonl> --inventory <report.json>` command once the library API is stable.
6. **Integrations.** Implement OpenTelemetry and API gateway adapters once the normalized schema is approved.

## MVP readiness criteria

The MVP is ready when it processes a stream of at least 100,000 metadata-only events with bounded memory usage, never emits forbidden payload fields, produces identical JSON for identical input, handles corrupted lines with diagnostics, and creates separate findings for undeclared targets/providers.

## Security principle

The runtime audit must be an **observer, not an executor**. It does not run commands from events, does not access URLs from `target` fields, does not read tool arguments and does not make access-granting decisions. Enforcement is a separate future component with its own threat model and approval process.

## Implemented in the current stage

The repository implements the `internal/runtime` library layer, which performs safe reading of normalized JSONL events, deterministic aggregation and matching against the static `scan.Report`. Rules `ACP-R001` through `ACP-R004` are added, including detection of undeclared targets, actual providers, production write activity and ambiguous agent matching.

The `agentctl runtime-audit <events> --inventory <report.json>` command is added. The `--source` flag selects `jsonl`, `otel-json` or `api-gateway`. The command supports text/json/SARIF output, `--baseline`, expiring `--suppressions`, atomic writes through the existing `--output` mechanism and the `--fail-on` CI threshold.

Snapshot comparison uses `agentctl runtime-diff before.json after.json`. The command shows added, removed and unchanged findings and supports `--format text|json|csv|html`. The diff compares stable finding IDs, so it can be used in nightly security reviews and regression CI checks.

Adapters accept metadata fields only. OpenTelemetry spans are converted using agent, tool, environment, provider and HTTP-status attributes. API Gateway records support snake_case and camelCase identifiers, JSONL and JSON arrays. Request and response payloads are neither read nor carried into the normalized event. Provider matching now works at the individual agent level: an actual provider counts as declared only when it belongs to a model listed in `agent.models`. Normalized JSONL rejects sensitive keys (`prompt`, `arguments`, `request_body`, `response_body`, `headers`, `authorization`, `token` and similar) and limits metadata field length.

Next stage: add the OpenTelemetry and API gateway adapters without changing the normalized event contract.

## References

[1]: https://opentelemetry.io/docs/specs/otel/ "OpenTelemetry Specification"

[2]: https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-tsp-section-100 "AICPA Trust Services Criteria"
