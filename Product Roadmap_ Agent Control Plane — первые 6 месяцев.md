# Product Roadmap: Agent Control Plane — первые 6 месяцев

**Версия:** 1.0  
**Горизонт:** 6 месяцев от старта разработки  
**Стратегическая цель:** доказать, что read-only Agent Control Plane регулярно находит реальные agent inventory, ownership, identity и permission gaps и за эту ценность готовы платить AI/platform/security teams.

## 1. Продуктовая стратегия MVP

Agent Control Plane не должен начинать как универсальная платформа управления автономными системами. Первая версия должна решать один узкий вопрос:

> **«Какие production AI-агенты реально существуют в компании, к каким tools и identities они подключены, кто за них отвечает и какие relationships требуют немедленного внимания?»**

MVP запускается в **read-only режиме** и не меняет production configuration, IAM или traffic. Это сокращает security review и позволяет быстро получить design partners. Основной вход — CLI/CI scanner, который объединяет данные из repositories, Kubernetes manifests, MCP configurations, OpenTelemetry traces и cloud metadata.

### Scope MVP

| Входит в первые 6 месяцев | Не входит в первые 6 месяцев |
|---|---|
| Discovery CLI | Автоматическое изменение IAM |
| GitHub/GitLab scan | Полноценный inline runtime proxy |
| Kubernetes/Docker metadata | Поддержка всех облаков и frameworks |
| MCP configuration scan | Полный SIEM replacement |
| OpenTelemetry metadata/traces | Автоматическая certification compliance |
| Agent inventory | Universal prompt-injection defense |
| Owner/model/tool/identity graph | Полная multi-agent orchestration |
| 10–15 evidence-based risk rules | LLM-as-a-judge для всех findings |
| GitHub/Jira/Slack remediation | Большая GRC-платформа |
| Self-hosted runner | Автоматическое исправление конфигураций |
| SSO/RBAC для pilot | Complex graph database infrastructure |

## 2. North Star Metric

### North Star Metric: Weekly Verified Production Agents — WVPA

**WVPA** — число production AI-агентов, которые за последние 7 дней имеют полный evidence-backed operational status:

1. агент найден через разрешённый repository, deployment или runtime source;
2. подтверждён environment и production status;
3. определён owner/team или явно зафиксирован ownership gap;
4. построена карта model → identity → tool/MCP → data/system хотя бы для критичных связей;
5. последняя проверка выполнена не более семи дней назад;
6. каждому critical/high-risk finding присвоен статус: open, remediating или accepted risk с owner и сроком пересмотра.

Формула:

```text
WVPA = count(production agents with fresh evidence-backed status)
```

### Почему именно эта метрика

Количество установок CLI или число созданных inventory-карточек легко накрутить и оно не доказывает ценность. WVPA показывает, что продукт поддерживает **актуальное и пригодное для принятия решений состояние агентной среды**. Он одновременно отражает adoption, data completeness, recurring usage и operational value.

### Цель на конец шестого месяца

| Показатель | M6 target |
|---|---:|
| Design partners | 10 активных |
| Paid pilots | 3–5 |
| Discovered agents | 800–1 000 |
| **WVPA** | **500–700** |
| Средняя coverage у активных клиентов | ≥80% production agents |
| Freshness | ≥90% verified agents scanned за последние 7 дней |
| Evidence completeness | ≥85% критичных связей имеют source evidence |
| High-risk remediation | ≥30% findings закрыто или принято в течение 14 дней |

## 3. Metric tree

| Уровень | Метрики | Для чего нужны |
|---|---|---|
| North Star | WVPA, production-agent coverage | Реальная ценность и recurring control |
| Activation | Time to First Verified Agent, first scan success, owner confirmation | Насколько быстро клиент получает результат |
| Data quality | Model/tool/identity completeness, evidence coverage, duplicate rate | Достоверность inventory |
| Risk value | High-risk findings/account, remediation rate, false-positive rate | Практическая security value |
| Engagement | Weekly active workspaces, repeat scans, new findings reviewed | Повторное использование |
| Conversion | Diagnostic→pilot, pilot→paid, expansion pipeline | Коммерческая проверка |
| Reliability | Scan success rate, ingestion latency, dashboard uptime | Операционная пригодность |
| Economics | ACV, CAC, onboarding hours, payback, gross margin | Устойчивость модели |

## 4. Годовые и шестимесячные product objectives

### Objective 1: Сделать agent inventory достоверным

К концу M2 пользователь должен подключить read-only источник, получить список агентов и увидеть evidence по каждой карточке. К концу M3 inventory должен обновляться автоматически и различать source-of-truth, inferred entity и unresolved entity.

### Objective 2: Превратить inventory в security decision tool

К концу M3 продукт должен находить over-permission, shared identity, missing owner, unknown MCP server и untracked production agent. К концу M4 каждое finding должно иметь evidence, severity, owner и remediation path.

### Objective 3: Доказать recurring value

К концу M5 минимум 60% активных design partners должны выполнять повторное сканирование еженедельно. К концу M6 минимум 80% активных клиентов должны использовать продукт не только для первоначального audit, но и для continuous inventory.

### Objective 4: Проверить willingness to pay

К концу M4 — первые paid pilots. К концу M6 — 3–5 платных пилотов, минимум 2 клиента с намерением перейти на annual contract и подтверждённый price corridor для Team/Business plans.

## 5. Roadmap по месяцам

## Месяц 1 — Discovery, threat model и технический фундамент

**Цель:** подтвердить проблему на реальных командах и не построить generic dashboard без evidence.

| Направление | Deliverables |
|---|---|
| Customer discovery | 15–20 интервью с AI/platform/security leads; 5 design partners в pipeline |
| Product definition | Final ICP, jobs-to-be-done, exclusion list, MVP success criteria |
| Data model | Agent, owner, team, model, identity, tool, MCP server, environment, finding, evidence |
| Security | Threat model, secret-handling policy, data retention policy, read-only architecture |
| CLI | `agentctl init`, source discovery, dry-run, local JSON report |
| UX | Low-fidelity inventory and finding flows |
| Research | 10–15 risk rules ranked by severity and evidence availability |

**Exit criteria:** минимум 5 компаний согласились предоставить sample repository/configuration или пройти read-only diagnostic; минимум 3 повторяющиеся pain patterns подтверждены у разных ICP; security boundaries приняты design partners.

**Метрики:** 20 interviews; 5 qualified design partners; 80% интервьюируемых не могут быстро показать полный agent inventory; Time to First Finding в лабораторном сценарии <60 минут.

## Месяц 2 — Read-only Discovery MVP

**Цель:** дать первый measurable outcome — список агентов и первичные риски за один scan.

| Направление | Deliverables |
|---|---|
| Sources | GitHub/GitLab repositories; Docker/Kubernetes manifests; MCP configs |
| Normalization | Entity resolver для agent/model/tool/identity/environment |
| Inventory | Карточки агентов, поиск, фильтры, duplicate detection |
| Risk engine | Первые 10 правил, severity и evidence path |
| UX | Dashboard: agents, owners, tools, risk summary |
| Integrations | GitHub App и экспорт JSON/CSV |
| Deployment | Local CLI + Dockerized API + basic hosted workspace |

**Exit criteria:** 5 design partners подключили хотя бы один источник; scan success rate ≥90%; первый результат появляется менее чем за 30 минут; минимум 100 агентов обнаружено на реальных или consented environments.

**Metrics target:** 5 active workspaces; 100–150 discovered agents; 70% agent records contain model/tool evidence; ≥80% findings reproducible from source evidence; TTFV <30 min.

## Месяц 3 — Evidence graph, ownership и recurring scan

**Цель:** превратить статический список в актуальную карту relationships и ownership gaps.

| Направление | Deliverables |
|---|---|
| Graph | Agent → model → identity → tool/MCP → system/data relationship view |
| Runtime | OpenTelemetry metadata ingestion; correlation with repository entities |
| Ownership | GitHub team mapping, manual confirmation, owner verification status |
| Risk | Shared identity, excessive permission, unknown MCP, untracked runtime agent |
| Recurring use | Scheduled scan, change detection, new/changed relationship alerts |
| Workflow | Slack notifications; GitHub/Jira issue creation |
| Analytics | Coverage, freshness, evidence completeness |

**Exit criteria:** 8 design partners; 250–350 discovered agents; минимум 100 WVPA; 70% high-risk findings имеют evidence и owner; weekly scan работает у 60% активных workspaces.

**Metrics target:** WVPA 100–150; scan success ≥95%; evidence completeness ≥75%; duplicate rate <10%; owner confirmation ≥60%.

## Месяц 4 — Pilot hardening и security readiness

**Цель:** сделать продукт пригодным для платного pilot и enterprise security review.

| Направление | Deliverables |
|---|---|
| Deployment | Self-hosted runner, Helm chart, private data path |
| Security | Secret redaction, encryption, audit log, least-privilege connector scopes |
| Access control | SSO/SAML или OIDC, RBAC, workspace separation |
| Findings | Severity tuning, accepted risk, remediation status, due date |
| Reliability | Retry, partial-scan handling, connector health, rate limits |
| Commercial | Paid pilot package, security questionnaire, DPA/security FAQ |
| Customer success | Weekly review template and remediation workshop |

**Exit criteria:** 3 paid pilots signed or in procurement; no critical secrets exposed in test audits; false-positive rate for top rules <25%; self-hosted runner successfully deployed at 2 customers.

**Metrics target:** 400–500 discovered agents; WVPA 200–300; ≥80% weekly freshness; ≥25% high-risk remediation/accepted-risk status within 14 days; onboarding <8 hours per customer.

## Месяц 5 — Policy-as-code, packaging и expansion wedge

**Цель:** перейти от inventory report к повторяемому control workflow.

| Направление | Deliverables |
|---|---|
| Policies | YAML policy-as-code для owner, provider, tool scope, environment и MCP allow-list |
| API | Public read API for inventory/findings; webhooks for changes |
| CI | Read-only CI check for new agent/tool/identity relationships |
| Product packaging | Community, Team и Business limits; usage/agent counting |
| Integrations | Jira/Slack hardening; optional OTel export |
| Content | Security report template, demo workspace, architecture docs |
| GTM | 10-account outbound sequence; OSS scanner launch; 2 case studies |

**Exit criteria:** 5 paid pilots or paid customers; 60% active workspaces run weekly scans; 3 customers use policy checks; at least 2 expansion opportunities into MCP Gateway or compliance evidence.

**Metrics target:** 600–750 discovered agents; WVPA 350–450; ≥80% production coverage in active accounts; activation rate ≥60%; pilot→paid conversion target ≥40%.

## Месяц 6 — v1 launch и проверка repeatability

**Цель:** доказать, что продукт можно регулярно внедрять и продавать за пределами founders’ network.

| Направление | Deliverables |
|---|---|
| Product v1 | Stable CLI, hosted dashboard, self-hosted runner, RBAC, policies, findings workflow |
| Distribution | Public docs, GitHub repository, install script, sample reports, security page |
| Sales | ICP-specific deck, pilot SOW, pricing page, referenceable case studies |
| Measurement | Cohort dashboard for WVPA, activation, coverage, remediation, retention |
| Partnerships | 2 conversations with observability/IAM/dev-platform ecosystems |
| Decision | Go / iterate / pivot review based on evidence |

**Exit criteria:** 10 active design partners; 3–5 paid pilots; 500–700 WVPA; 80% weekly production coverage among active customers; 3 referenceable case studies; at least 2 customers ready for annual contract.

**Metrics target:** 800–1,000 discovered agents; WVPA 500–700; scan success ≥97%; evidence completeness ≥85%; high-risk remediation or accepted risk ≥30% within 14 days; NPS/design-partner satisfaction ≥40 or equivalent qualitative advocacy.

## 6. Release gates

| Gate | Must be true before proceeding |
|---|---|
| Discovery → Build | Pain repeated in ≥3 ICPs; ≥5 design partners; clear read-only security boundary |
| M2 → M3 | Scan works on ≥5 real accounts; TTFV <30 min; findings have evidence |
| M3 → Paid pilot | Recurring scan works; ownership/identity gaps visible; customer asks for remediation workflow |
| M4 → Packaging | Private deployment and security review passed; onboarding <8 hours |
| M5 → v1 | Weekly usage and findings review repeat; at least 3 paid pilots; no single founder manually operating every scan |
| M6 → Scale | WVPA growth, customer retention, paid conversion and expansion evidence support next round of hiring/investment |

## 7. Команда и operating model

Минимальная команда на 6 месяцев — 4–5 человек:

| Роль | Основная зона ответственности |
|---|---|
| Product/founder | ICP, customer discovery, roadmap, sales и design partners |
| Platform/backend engineer | Data model, API, collectors, risk engine |
| Security/infrastructure engineer | CLI, K8s, secrets, self-hosted runner, threat model |
| Frontend/product engineer | Inventory, graph, findings workflow |
| Part-time design/DevRel | Docs, OSS distribution, case studies, onboarding |

Каждую неделю команда должна проводить customer evidence review: какие findings были полезны, какие false positives возникли, какие источники не подключились и какие действия клиент выполнил после finding. Roadmap нельзя оценивать только по shipped features.

## 8. Риски и mitigations

| Риск | Ранний сигнал | Mitigation |
|---|---|---|
| Dashboard без operational value | Пользователи смотрят inventory один раз | Добавить recurring scan, owner workflow и remediation status |
| Слишком широкий scope | Каждый customer просит новый collector | Сначала 3–4 источника и фиксированный ICP |
| Security review блокирует SaaS | Клиенты не передают configs/traces | Read-only/self-hosted runner, redaction, local mode |
| Низкая достоверность entity resolution | Много duplicates и inferred records | Evidence levels, manual confirmation, explicit uncertainty |
| Конкуренция с AI security platforms | Enterprise сравнивает с full-suite vendors | Developer-first wedge, low-friction scanner, affordable Team plan |
| Низкая willingness to pay | Все просят бесплатный scan | Бесплатный discovery report ограничить; paid remediation/policy workflow |
| Длинный enterprise cycle | Пилоты не стартуют за 30 дней | Mid-market SaaS/AI-native first; enterprise use as reference later |

## 9. North Star review cadence

Метрики пересматриваются еженедельно на product review и ежемесячно на strategy review. Нельзя считать агента verified, если evidence устарело, owner неизвестен или production status не подтверждён. Важнее 300 достоверных WVPA, чем 3 000 автоматически созданных карточек.

В конце M6 решение должно приниматься по четырём вопросам:

1. Увеличивается ли WVPA после каждой недели, а не только после onboarding?
2. Возвращаются ли клиенты для recurring scan и remediation?
3. Существуют ли findings, за которые security/platform team готова платить?
4. Можно ли внедрить следующий аккаунт менее чем за один рабочий день без участия founders?

Если ответы положительны, следующий этап — MCP Security Gateway и runtime enforcement. Если растёт только inventory, но нет remediation и оплаты, продукт следует сузить до security discovery scanner или изменить ICP.
