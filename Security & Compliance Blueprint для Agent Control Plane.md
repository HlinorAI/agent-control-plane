# Security & Compliance Blueprint для Agent Control Plane

**Версия:** 1.0  
**Назначение:** безопасный discovery и контроль внутренних, внешних и чужих AI-агентов  
**Статус:** blueprint для MVP и первых production pilots  
**Основной принцип:** read-only by default, evidence-first, metadata-only by default, no arbitrary code execution

> **Важно.** Этот документ описывает инженерные и организационные меры контроля, а не является юридическим заключением или гарантией соответствия конкретному закону. Applicability GDPR, EU AI Act, SOC 2, ISO 27001/42001 и отраслевых требований зависит от роли компании, типов данных, юрисдикции и конкретных use cases.

## 1. Security objectives

Agent Control Plane должен давать security/platform команде актуальную карту агентов, identities, models, tools и data/system relationships, не создавая новый privileged attack path.

| Objective | Обязательный результат |
|---|---|
| Confidentiality | Не принимать и не сохранять raw secrets и лишние payloads |
| Integrity | Каждая сущность и связь имеют provenance, hash, timestamp и confidence |
| Tenant isolation | Невозможен cross-workspace read/write path |
| Least privilege | Collector и integrations имеют только минимальные read scopes |
| Safe handling | Чужой agent code/config считается недоверенным input |
| Accountability | Все изменения findings, policies, ownership и exceptions аудируются |
| Resilience | Большой, вредоносный или сломанный source не нарушает работу control plane |
| Compliance evidence | Можно показать policy, test result, access log, scan provenance и incident trail |

NIST AI RMF задаёт добровольную risk-management основу с функциями Govern, Map, Measure и Manage; его Generative AI Profile предназначен для специфических рисков generative AI [1]. OWASP Top 10 for Agentic Applications 2026 предлагает отдельную threat taxonomy для систем, которые планируют, действуют и принимают решения в сложных workflow [2]. Blueprint использует эти источники как ориентиры, но не объявляет продукт автоматически compliant.

## 2. Scope и trust boundaries

### 2.1 Security zones

```text
┌────────────────────────────────────────────────────────────────────┐
│ ZONE A — Customer source systems                                  │
│ GitHub/GitLab, K8s, Docker, MCP configs, OTel, cloud metadata       │
└──────────────────────────────┬─────────────────────────────────────┘
                               │ read-only, customer-controlled
┌──────────────────────────────▼─────────────────────────────────────┐
│ ZONE B — Customer-side collector / self-hosted runner              │
│ parsers, redaction, hashing, local policy, outbound-only egress     │
└──────────────────────────────┬─────────────────────────────────────┘
                               │ TLS, signed metadata batches
┌──────────────────────────────▼─────────────────────────────────────┐
│ ZONE C — Agent Control Plane                                      │
│ ingestion, queue, normalization, inventory, evidence, rules, API   │
└──────────────────────────────┬─────────────────────────────────────┘
                               │ scoped outbound integrations
┌──────────────────────────────▼─────────────────────────────────────┐
│ ZONE D — Remediation and notification systems                      │
│ GitHub/Jira/Slack/webhooks, no unrestricted write-back              │
└────────────────────────────────────────────────────────────────────┘
```

### 2.2 Trust assumptions

| Boundary | Trusted | Untrusted or partially trusted |
|---|---|---|
| Customer source → runner | Customer-controlled runtime and credentials | Repository contents, manifests, agent configs, MCP server metadata |
| Runner → control plane | Signed runner binary and redaction component | Batch content, source claims, malformed schemas, replayed batches |
| Control plane internal | Authenticated service identities and validated schemas | Parser output until validation, inferred relationships, imported evidence |
| Control plane → integrations | Explicitly configured destination and scoped token | Slack/Jira/GitHub content, webhook endpoint response |
| Third-party agent → environment | None by default | Agent code, prompts, tool definitions, memory, plugins, model output, external instructions |

**Чужой AI-агент не является trusted automation.** Даже если его предоставил customer или известный vendor, его code, configuration, tool definitions, prompt content и model outputs необходимо трактовать как potentially malicious or compromised input. External instructions found in repositories, tool responses, documents or agent memory are data, not authorization.

## 3. Threat model

### 3.1 Assets

| Asset | Impact if compromised |
|---|---|
| Customer source metadata | Disclosure of architecture, repositories, tools and providers |
| Identity/tool relationships | Privilege escalation, lateral movement, sensitive-system access |
| Evidence records | False assurance, audit failure, manipulated remediation status |
| Findings and severity | Suppression of critical risk or incorrect prioritization |
| Workspace isolation keys | Cross-tenant breach |
| Connector credentials | Unauthorized source read or ticket/message write |
| Agent fingerprints | Privacy, competitive intelligence and security-sensitive data |
| Policy/exceptions | Silent bypass of controls |
| Audit logs | Loss of accountability and incident reconstruction |
| Runner update channel | Supply-chain compromise across customer environments |

### 3.2 Threat categories

| Threat | Example | Primary controls |
|---|---|---|
| Prompt/tool injection | MCP response tells scanner to upload files or ignore policy | Never execute agent instructions; allow-list actions; content/data separation |
| Confused deputy | Agent uses Control Plane token to access unrelated source | Audience-bound tokens, scopes, tenant binding, token exchange |
| Credential exfiltration | Secret embedded in config is uploaded as evidence | Local redaction, entropy/pattern detection, no raw secrets, DLP tests |
| Malicious repository | Parser executes setup.py, Dockerfile or postinstall script | Parse as data, no shell execution, sandboxed optional analysis |
| Poisoned inventory | Fake source claims owner or production status | Provenance, source trust levels, conflict resolution, manual confirmation |
| Over-privileged connector | GitHub App can write code despite read-only need | Least privilege, installation-time scope check, periodic revalidation |
| Cross-tenant access | Workspace A queries Workspace B IDs | RLS, authorization middleware, object-level tests, opaque IDs |
| Replay/tampering | Old clean batch overwrites newer risky state | Nonce, monotonic scan version, timestamp, signed batch, idempotency |
| Parser DoS | Huge YAML, deeply nested JSON, zip bomb | Size/depth/time limits, streaming parser, quotas, circuit breakers |
| Supply-chain compromise | Compromised collector release ships malicious code | Signed releases, SBOM, provenance, dependency pinning, staged rollout |
| Finding suppression | User marks critical finding accepted forever | Role separation, expiry, justification, immutable audit event |
| Webhook abuse | Notification endpoint triggers SSRF or data leak | Egress allow-list, URL validation, no internal IPs, secret-safe payloads |
| Agent action escalation | Future control feature allows agent to approve its own action | Human approval, separation of duties, non-agent approver, deny-by-default |

### 3.3 Abuse cases specific to чужие агенты

1. **Агент возвращает инструкции вместо данных.** Collector должен сохранить content hash и metadata, но не выполнять инструкцию и не передавать её в privileged workflow.
2. **Агент подменяет identity.** Identity claims from agent output имеют низкий confidence, пока не подтверждены deployment/IAM/OTel source.
3. **Агент предлагает добавить новый MCP server.** Это создаёт change proposal, а не автоматически approved relationship.
4. **Агент скрывает tool call или меняет название tool.** Runtime evidence и независимые source collectors должны позволять сопоставить observed calls с inventory.
5. **Агент просит сканер отправить secrets для диагностики.** Сканер должен отказать, залогировать безопасный reason и продолжить без secret value.
6. **Агент является намеренно вредоносным тестовым образцом.** Его разрешается запускать только в изолированном sandbox, без production credentials, network egress по умолчанию и доступа к host socket.

## 4. Secure onboarding чужого AI-агента

### Stage 0 — Classification

До подключения определить provider, owner, purpose, environment, autonomy level, data domains, tools, identities, model, deployment artifact, external endpoints и rollback/disable path. Присвоить trust tier:

| Tier | Пример | Default treatment |
|---|---|---|
| T0 | Static config или source reference без execution | Можно анализировать read-only |
| T1 | Customer-owned agent в sandbox | Можно запускать с ограничениями |
| T2 | Third-party agent с tools в non-production | Только отдельный sandbox, explicit approval |
| T3 | Third-party agent с production write access | Не подключать к MVP runtime; только metadata discovery |
| T4 | Unknown/unverified agent | Treat as hostile; no execution and no credentials |

### Stage 1 — Admission checks

Проверить provenance, signed image/package, digest, SBOM, declared tools, network endpoints, requested permissions, model/provider, data classification, license and vulnerability status. Отсутствие provenance не должно блокировать discovery metadata, но должно повысить risk finding.

### Stage 2 — Permission review

Сопоставить requested capability с declared purpose. Для каждого tool и identity создать matrix:

| Dimension | Required evidence |
|---|---|
| What | Exact tool/API/action |
| Who | Human/team/service identity |
| Where | Environment, namespace, account, region |
| Data | Classification and allowed domains |
| When | Schedule, TTL, expiry |
| Why | Business purpose and owner |
| How | Approval, rate limit, rollback |

Любое write/admin capability требует explicit owner, environment boundary, approval path и test evidence. Default policy — deny until approved.

### Stage 3 — Safe observation

Начинать с static discovery, затем metadata-only runtime observation, затем sandbox replay. Не подключать чужой агент напрямую к production credentials только ради telemetry. Если нужны реалистичные tool calls, использовать synthetic data and scoped test accounts.

### Stage 4 — Ongoing verification

Переоценивать artifact digest, tool list, identity scope, owner, deployment environment и policy status при каждом change event и минимум еженедельно для production agents.

## 5. Security controls blueprint

### 5.1 Collector and runner controls

| Control | Implementation | Test evidence |
|---|---|---|
| Read-only scopes | GitHub App read scopes; K8s Role, not ClusterRole; cloud read-only role | Permission diff and denied-write tests |
| Local redaction | Secret patterns, entropy detector, structured field deny-list | Secret corpus with known and obfuscated secrets |
| No code execution | Parsers process bytes/AST only; disable subprocess and package hooks | Static scan + runtime syscall policy |
| Outbound-only | Egress to approved API domains; no inbound listener | Network policy and packet tests |
| Signed batches | Workspace-scoped short-lived token, nonce, signature, schema version | Replay/tamper/expired-token tests |
| Resource limits | File, archive, AST depth, CPU, memory and time quotas | Fuzz and DoS tests |
| Secure update | Signed binary/container, SBOM, provenance, staged rollout | Signature failure and rollback tests |

### 5.2 Control-plane controls

| Control | MVP requirement |
|---|---|
| Authentication | OIDC for users; service tokens for runner; short TTL |
| Authorization | RBAC: Viewer, Analyst, Remediator, Admin; object-level workspace checks |
| Tenant isolation | `workspace_id` on all domain objects, RLS where hosted, negative authorization tests |
| Encryption | TLS 1.2+ in transit; managed KMS encryption at rest; key rotation policy |
| Evidence minimization | Store locator/hash/redacted excerpt; raw source only opt-in and time-limited |
| Auditability | Append-only audit events for access, policy, finding, owner and exception changes |
| Availability | Queue backpressure, retries, dead-letter, scan isolation, rate limits |
| Secure defaults | No auto-remediation, no arbitrary webhooks, no raw payload collection |
| Admin separation | Platform admin cannot silently alter customer evidence; dual control for sensitive changes |
| Retention | Workspace-configurable retention; default short retention for raw/temporary artifacts |

### 5.3 Risk engine controls

Risk rules must be deterministic, versioned and explainable. A finding contains `rule_id`, rule version, severity, affected entities, evidence references, confidence, timestamp, owner, status, due date and remediation hint.

Recommended MVP rules:

| Rule | Detection | Negative test |
|---|---|---|
| Ownerless production agent | Production evidence exists, owner missing | Non-production ownerless agent does not become High automatically |
| Shadow agent | Runtime fingerprint has no source inventory | Same agent observed in two collectors deduplicates |
| Shared identity | Unrelated agents use same powerful identity | Same team-approved shared identity has documented exception |
| Excessive write scope | Write/admin tool exceeds declared purpose | Read-only tool does not trigger |
| Unknown MCP server | MCP server not in allow-list or registry | Approved server with changed metadata creates change finding |
| Dev credential in prod | Environment mismatch in identity evidence | Explicitly scoped test credential is not critical |
| Stale relationship | No fresh verification before TTL | Recently scanned entity remains fresh |

## 6. Test strategy

### 6.1 Test layers and cadence

| Layer | Scope | Cadence | Release gate |
|---|---|---|---|
| Unit | Redaction, parsers, normalization, rules, authorization | Every PR | 100% critical rule cases pass |
| Schema/contract | CLI batch, API, OTel metadata, version compatibility | Every PR | No breaking contract without migration |
| Integration | Postgres, queue, object store, connectors | Every PR/nightly | Happy path and failure path pass |
| Fuzz/property | YAML/JSON/MCP/AST parsers, batch decoder | Nightly/weekly | No crash, escape or unbounded resource use |
| SAST/SCA | Go/TS dependencies, secrets, IaC, Docker | Every PR/release | No critical unaccepted findings |
| DAST/API | Auth, RLS, SSRF, injection, rate limits | Nightly/release | No High/Critical open |
| Red team | Agent/tool injection, confused deputy, supply chain | Monthly/pre-GA | All critical attack paths mitigated or accepted |
| DR/BCP | Backup restore, queue loss, region failure | Quarterly/pre-GA | RTO/RPO targets met |

### 6.2 Core security test cases

| ID | Test | Expected result |
|---|---|---|
| SEC-001 | Upload repository containing API keys, JWTs, private keys and secrets in comments | Values never reach persistent evidence store; redaction event recorded |
| SEC-002 | Obfuscate secret with base64, split strings, Unicode and whitespace | Detector catches high-confidence variants or marks uncertainty without uploading raw value |
| SEC-003 | Repository contains malicious `setup.py`, `package.json` postinstall and Dockerfile | Nothing executes; parser returns structured finding or safely skips |
| SEC-004 | YAML/JSON billion-laughs/deep nesting/zip bomb | Bounded failure, no worker starvation or host impact |
| SEC-005 | Batch signature altered by one byte | API rejects batch and records tamper event |
| SEC-006 | Replay old valid batch after newer scan | API rejects stale version or preserves newer state |
| SEC-007 | Expired, wrong-workspace and wrong-audience token | 401/403; no metadata leakage |
| SEC-008 | Viewer requests another workspace agent by ID | 403/404 without existence oracle |
| SEC-009 | Analyst attempts admin policy change | Denied and audited |
| SEC-010 | User accepts Critical finding without reason/expiry | Denied; accepted risk requires reason, owner and expiry |
| SEC-011 | Finding evidence includes prompt injection text | UI labels it as untrusted evidence; no action is executed |
| SEC-012 | MCP metadata advertises a tool that requests secrets | Stored as untrusted declaration; policy rule flags it |
| SEC-013 | Webhook URL targets localhost, metadata IP or internal DNS | Request blocked by SSRF policy |
| SEC-014 | Webhook response contains instruction to change policy | Treated as data; no policy mutation |
| SEC-015 | Compromised collector attempts arbitrary API endpoint | Network and server audience validation reject it |
| SEC-016 | Cross-tenant query via filters, sort, export and GraphQL-like paths | Zero cross-tenant records across all access paths |
| SEC-017 | Malicious or unsigned runner update | Update rejected and rollback remains available |
| SEC-018 | Agent tool call changes from read to write between scans | Change finding created with evidence and owner notification |
| SEC-019 | OTel metadata contains personal data or prompt payload | Only allow-listed metadata persisted; payload rejected/redacted |
| SEC-020 | Queue retries same job 10 times | Idempotent processing, bounded retries, dead-letter status |
| SEC-021 | Customer revokes connector permission | Next scan fails closed; prior evidence remains auditable |
| SEC-022 | Agent claims owner in output conflicting with IAM/source data | Higher-trust source wins; conflict finding created |
| SEC-023 | Production agent loses disable/rollback path | Medium/High finding created according to policy |
| SEC-024 | Unknown external model provider appears | Provider is unverified, not auto-approved |
| SEC-025 | Sandbox agent attempts network exfiltration | Egress denied or allow-listed; event captured |

### 6.3 AI-specific evaluation

Для Agent Control Plane не нужно полагаться на LLM в критическом risk decision path. Если LLM используется для grouping, summarization или suggested remediation, выполнять отдельный eval suite:

- prompt injection resistance;
- evidence citation accuracy;
- no unsupported severity changes;
- no secret reproduction;
- no policy override from content;
- stable output under paraphrase;
- abstention when evidence is missing;
- human approval before any write action.

Acceptance threshold для production pilot: zero critical security decisions driven solely by an LLM; ≥95% evidence links in generated summaries point to an existing evidence record; unsupported claims must be labeled unknown.

## 7. Secure handling of execution and sandboxing

### Default rule

**Не запускай чужих AI-агентов для discovery MVP.** Анализируй source/configuration/metadata as data. Это снижает attack surface и делает read-only promise проверяемым.

### Если execution необходим

| Layer | Mandatory control |
|---|---|
| Isolation | Ephemeral VM or hardened container; no host Docker socket |
| Identity | Dedicated non-human identity, no production credentials |
| Filesystem | Read-only base image, temporary workspace, no home directory secrets |
| Network | Deny-all egress; explicit allow-list; DNS logging |
| Syscalls | Seccomp/AppArmor/gVisor or microVM policy |
| Resources | CPU, RAM, process, file, timeout and output quotas |
| Tools | Synthetic/stub tools only; no arbitrary browser/cloud/admin tools |
| Data | Synthetic or redacted fixtures; no customer PII/secrets |
| Observation | Full process, network, file and tool-call audit |
| Teardown | Destroy sandbox and ephemeral credentials after run |

Не считать container isolation достаточной для hostile code при наличии high-value secrets. Для действительно недоверенного execution использовать isolated VM/microVM, а не только Docker.

## 8. Compliance blueprint

### 8.1 Control mapping

| Control area | NIST AI RMF | SOC 2 / ISO-style evidence | EU AI Act relevance |
|---|---|---|---|
| Governance and scope | Govern | Policies, roles, risk register | Shows accountability and intended purpose |
| Agent inventory and classification | Map | Asset inventory, system register | Supports documentation and risk classification |
| Logging and traceability | Measure/Manage | Immutable audit logs, retention test | Traceability is explicit for high-risk systems [3] |
| Human oversight | Manage | Approval matrix, separation of duties | Human oversight requirement for high-risk use cases [3] |
| Security and robustness | Measure/Manage | SAST, DAST, pen test, vuln management | Cybersecurity and robustness obligations [3] |
| Incident response | Govern/Manage | IR plan, tabletop, notification record | Serious incident/malfunction monitoring and reporting [3] |
| Data minimization | Govern/Map | Data map, DPA, retention/deletion tests | Privacy and fundamental-rights risk context |
| Model/provider governance | Map/Measure | Vendor due diligence, model register | GPAI/supply-chain role depends on use case |
| Change management | Manage | Release approval, signed artifacts | Supports post-market monitoring and technical documentation |

EU AI Act applicability is use-case specific. The European Commission describes a risk-based framework, identifies high-risk categories and lists logging, documentation, human oversight, robustness, cybersecurity and accuracy obligations for them; it does not mean every internal agent is high-risk [3].

### 8.2 Evidence pack for a customer pilot

Хранить в versioned compliance repository:

1. System description and data-flow diagram.
2. Trust-boundary and threat-model document.
3. Asset and agent inventory export.
4. Data classification and retention policy.
5. Connector permission matrix.
6. Secure SDLC policy and code review records.
7. SBOM, dependency scan and release provenance.
8. Secret-redaction test report.
9. Tenant-isolation and authorization test report.
10. Penetration-test summary and remediation register.
11. Vulnerability disclosure and patch SLAs.
12. Access review and audit-log samples.
13. Backup/restore and disaster-recovery test.
14. Incident response plan and tabletop record.
15. Subprocessor/vendor inventory and DPA status.
16. Customer-specific accepted-risk register.
17. AI system/agent register and intended-purpose classification.
18. Human-oversight and escalation matrix.

Не заявлять SOC 2, ISO 27001/42001 или EU AI Act certification до прохождения соответствующего audit/assessment. До этого использовать формулировки «controls designed to support», «readiness evidence» и «customer-configurable compliance evidence».

## 9. Access control and identity blueprint

### Roles

| Role | Read inventory | Read evidence | Change finding | Change policy | Manage connectors |
|---|---:|---:|---:|---:|---:|
| Viewer | Yes | Redacted only | No | No | No |
| Analyst | Yes | Yes, scoped | Status/owner | No | No |
| Remediator | Yes | Yes, scoped | Yes | No | No |
| Workspace Admin | Yes | Yes | Yes | Yes, with audit | Yes, scoped |
| Platform Admin | Operational metadata only | No customer content by default | No customer decision | No | No |

Все access checks должны быть object-level, а не только route-level. Экспорт evidence требует отдельного permission и audit event. Platform operator не должен читать customer evidence без break-glass procedure, reason, approval и post-event review.

### Identity lifecycle

1. Connector installation creates a workspace-scoped identity.
2. Token receives minimal audience, scopes and TTL.
3. Every use is logged with actor, workspace, source and operation.
4. Rotate/revoke on owner change, incident, inactivity or scope change.
5. Review active identities monthly during pilot and quarterly after stabilization.
6. Expire accepted risks and temporary sandbox credentials automatically.

## 10. Incident response

### Severity

| Severity | Definition | Initial target |
|---|---|---:|
| SEV-0 | Active cross-tenant exposure, credential exfiltration or malicious code execution in customer environment | Contain immediately; executive/security escalation within 30 min |
| SEV-1 | High-confidence customer data exposure, compromised runner, critical auth bypass | Contain within 1 hour; customer notification assessment within 4 hours |
| SEV-2 | Single-workspace integrity issue, serious false negative, connector abuse | Triage within 1 business day |
| SEV-3 | Localized bug, low-risk data quality or non-security degradation | Triage within 3 business days |

### Response playbook

1. Detect and preserve evidence without modifying attacker artifacts.
2. Assign incident commander and security owner.
3. Disable affected token, connector, runner version or integration.
4. Freeze risky writes and move affected workspace to read-only safe mode.
5. Determine blast radius by workspace, source, time window and evidence access logs.
6. Rotate credentials and revoke compromised identities.
7. Notify affected customers according to contract and applicable law.
8. Patch, add regression test and verify containment.
9. Restore from known-good state if integrity is affected.
10. Conduct blameless postmortem with root cause, control gap and owner/date for remediation.
11. Update threat model, rule set, documentation and customer evidence pack.

### Break-glass

Break-glass access must be disabled by default, time-limited, reason-bound, approved by two people for customer content and automatically generate a high-priority audit event. Never use break-glass to bypass a customer’s data-residency or retention commitment.

## 11. Release and compliance gates

### Before first design-partner pilot

- Threat model reviewed by security owner.
- Read-only permissions validated for every connector.
- Secret redaction tests pass on known corpus.
- Cross-tenant authorization tests pass.
- No arbitrary code execution in parsers.
- Audit events exist for auth, evidence access and finding changes.
- Customer data-flow, retention and deletion behavior documented.
- Self-hosted runner has outbound-only policy.
- Security questionnaire and incident contact are ready.

### Before paid pilot

- SAST/SCA/DAST clean of open Critical and unaccepted High.
- Signed runner/image, SBOM and rollback path.
- Penetration test of API and dashboard.
- Tenant isolation negative tests automated in CI.
- Backup/restore test complete.
- Incident tabletop completed.
- Subprocessor and data residency disclosures ready.
- Customer-specific risk acceptance documented.

### Before general availability

- Independent penetration test completed.
- Vulnerability disclosure policy published.
- Annual access review process operational.
- Formal risk register and control owners assigned.
- Evidence pack generated automatically from CI and operations.
- RTO/RPO validated.
- Customer deletion/export workflow tested.
- SOC 2/ISO readiness gap assessment completed if those attestations are part of GTM.

## 12. Security KPIs

| Metric | M3 target | M6 target |
|---|---:|---:|
| Critical secrets uploaded to persistent store | 0 | 0 |
| Cross-tenant authorization defects | 0 | 0 |
| Critical open vulnerabilities | 0 | 0 |
| High vulnerabilities past SLA | 0 | 0 |
| Scan parser crash rate | <0.5% | <0.1% |
| Successful secret-redaction test cases | ≥98% | ≥99.5% |
| Signed-batch rejection coverage | 100% negative tests | 100% |
| Audit event coverage of sensitive actions | ≥95% | ≥99% |
| Mean time to revoke compromised token | <30 min | <15 min |
| Security incident tabletop completion | 1 | quarterly cadence |
| High-risk findings with evidence | ≥80% | ≥90% |
| Findings with owner and expiry | ≥70% | ≥90% |

## 13. Ownership model

| Area | Owner | Backup / reviewer |
|---|---|---|
| Threat model | Security engineer | CTO/founder |
| Collector permissions | Platform engineer | Customer security champion |
| Data retention | Privacy/legal owner | Product lead |
| Auth/RBAC | Backend engineer | Security engineer |
| Release signing/SBOM | DevOps/platform | Security engineer |
| Risk rules | Product + security | Design partner reviewers |
| Incident response | Incident commander | CTO + customer success |
| Compliance evidence | Compliance owner | External assessor when applicable |

## 14. Final design decisions

1. **Do not execute foreign agents in the discovery path.** Treat their code, prompts, tool descriptions, outputs and instructions as untrusted data.
2. **Do not store secrets or full payloads by default.** Persist metadata, hashes, redacted excerpts and provenance.
3. **Do not make the LLM the final security authority.** Use deterministic rules for severity and policy decisions.
4. **Do not add runtime enforcement in the first release.** First prove inventory, evidence, ownership and recurring findings.
5. **Do not promise certification.** Produce audit-ready evidence and map controls to the customer’s chosen framework.
6. **Do use self-hosted runner for sensitive customers.** Keep raw source access inside the customer boundary and send only approved metadata outward.

## References

[1]: https://www.nist.gov/itl/ai-risk-management-framework "NIST AI Risk Management Framework"

[2]: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ "OWASP Top 10 for Agentic Applications for 2026"

[3]: https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai "European Commission — AI Act regulatory framework"

[4]: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization "Model Context Protocol — Authorization specification"

[5]: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf "NIST AI RMF: Generative AI Profile"
