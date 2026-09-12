# Changelog

All notable changes to Agent Control Plane are documented here.

## [0.1.0-alpha.3] - 2026-09-12

### Added

- Runtime audit ingestion for JSONL, OpenTelemetry JSON, and API Gateway metadata.
- Streaming runtime aggregation with bounded input handling and agent-specific provider matching.
- Versioned `runtime.v1` event schema.
- Runtime findings with SARIF 2.1.0 export, JSON baseline support, and expiring suppressions.
- Rejection of sensitive runtime metadata fields, including prompts, arguments, bodies, headers, authorization data, tokens, and secrets.
- Deterministic `runtime-diff` snapshots with text, JSON, CSV, and HTML output.
- Read-only metadata normalizers for GitHub, GitLab, Docker, and Kubernetes.
- Metadata-only cloud audit normalization for AWS, GCP, and Azure.
- Review-only `policy-draft.v1` generation from runtime activity and correlated cloud resources.
- Adversarial and fuzz checks covering runtime parsers, metadata handling, and connector sanitization.

### Security and boundaries

This alpha remains a local, deterministic, read-only analysis tool. It does not execute scanned content, resolve credentials, contact external APIs from the scan path, read secret values, modify IAM, block traffic, or enforce generated policies. Policy drafts always require human review.

### Verification

The release workflow runs the full test suite, race tests, `go vet`, fuzz payload validation, and the long-running runtime fuzz gates before GoReleaser publishes platform archives and checksums.

## [0.1.0-alpha.2]

Previous public alpha release.
