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
