# Security Policy

## Scope

Agent Control Plane is a read-only, local scanner for repository and configuration metadata. It treats scanned content as untrusted data and does not execute repository code, hooks, prompts, tool responses or agent instructions.

The public alpha is not a hosted control plane, runtime proxy, IAM remediator or compliance certification.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's GitHub Security Advisories page. Do not open a public issue for an unpatched vulnerability or include real credentials, production payloads or customer data.

Include:

- affected commit, version or workflow;
- a minimal reproduction that contains no secrets;
- impact and attack prerequisites;
- a suggested mitigation, if known.

We will acknowledge actionable reports, assess impact and coordinate a fix or mitigation before public disclosure when practical.

## Security expectations

- Never commit real credentials, private keys, customer data or production payloads.
- Keep fixture secrets synthetic and verify that reports do not contain them.
- Review SARIF findings before treating them as production security decisions.
- Run the scanner with the minimum filesystem permissions required for the target repository.
- Do not treat heuristic inventory as proof of production status or authorization.

## Suspicious payload quarantine

Any payload rejected by `cmd/fuzzpayloadcheck` or discovered by fuzzing is untrusted data until reviewed. Do not execute it, pass it to a model provider or MCP server, open it in an auto-preview editor, or copy raw content into issues, chat, tickets or public artifacts.

Use this flow:

```text
validator reject
  -> private quarantine
  -> metadata-only offline triage
  -> secret and execution-risk assessment
  -> delete, restricted keep, scrub and promote, or incident escalation
```

Record only safe metadata in a machine-readable quarantine record. Use [`security/quarantine-record.example.json`](security/quarantine-record.example.json) as the template. The record must include the payload hash, source commit/run, validator codes, classification, owner, reviewer, status, retention deadline and private raw-artifact locator. Never place the raw payload or a suspected secret in the record.

Initial triage must use a disposable offline workspace with no credentials, network, process execution, package installation, Docker/Kubernetes socket or writable host filesystem. Inspect bytes and bounded JSON tokens only. If a real credential or customer data is plausible, stop analysis, preserve the hash, notify the responsible security owner and begin rotation/revocation assessment without attempting to validate the credential against a service.

A payload may enter `testdata/fuzz/**` only after it is synthetic, minimized, scrubbed, validator-approved, linked to a manifest case with an invariant and reproduction command, and reviewed by an owner outside the person who classified a possible secret. High/Critical cases require a private vulnerability-management record and SLA before promotion. External Slack, Telegram, Jira and PagerDuty delivery remains disabled unless explicitly enabled with dedicated least-privilege credentials.

Minimum response targets:

- possible real secret: immediate security-owner escalation;
- code-execution or network escape: immediate Critical escalation and release block;
- customer or proprietary data: security/privacy review within one hour;
- High parser/runtime regression: runtime owner and vulnerability-management record within one business day;
- ambiguous synthetic payload: corpus maintainer and security review within two business days.
