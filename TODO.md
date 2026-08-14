# Backlog

## Strategy alignment

- [x] Подключить product roadmap и regional strategy к проектной документации.
- [x] Зафиксировать WVPA как North Star Metric.
- [x] Выбрать США/Канаду первым beachhead-регионом.
- [ ] Зафиксировать региональные exclusions и не смешивать evidence между рынками.
- [ ] Определить минимальный набор полей для freshness/evidence completeness/owner verification.

## P0 — критично для первого работающего прототипа

### Product validation

- [ ] Зафиксировать one-sentence market definition и список exclusions.
- [ ] Определить минимальные признаки production agent для ICP.
- [ ] Подготовить 10–15 problem-interview вопросов.
- [ ] Составить проверяемый shortlist из 10 потенциальных design partners.
- [ ] Согласовать scope read-only diagnostic и критерий трёх полезных findings.
- [ ] Провести 15–20 интервью в первом beachhead-регионе.
- [ ] Подтвердить минимум 3 повторяющихся pain patterns.
- [ ] Получить 5 qualified design partners до перехода к полноценной разработке.

### Проект и CLI

- [ ] Инициализировать Go-модуль с командами и строгими настройками.
- [ ] Создать команду `agentctl scan <path>`.
- [ ] Добавить `agentctl init` для выбора workspace и approved sources.
- [ ] Добавить параметры `--dry-run`, `--format json|text` и `--output`.
- [ ] Возвращать ненулевой exit code при ошибке сканирования.
- [ ] Не читать значения секретов и не отправлять данные наружу.

### Контракт данных

- [ ] Описать типы `Repository`, `Agent`, `Model`, `Tool`, `Identity`, `Finding`, `Evidence`.
- [ ] Определить стабильные ID и правила дедупликации сущностей.
- [ ] Зафиксировать JSON-схему отчёта.
- [ ] Добавить версию схемы отчёта.
- [ ] Описать canonical relationships и типы evidence/confidence.
- [ ] Добавить OpenAPI 3.1 contract для будущего ingestion/API слоя.

### Git collector

- [ ] Сканировать только разрешённый root path.
- [ ] Определять вероятные agent entrypoints по конфигурации и импортам.
- [ ] Извлекать model provider/model name.
- [ ] Извлекать tool definitions и references на MCP.
- [ ] Определять repository path и environment, если они явно указаны.
- [ ] Сохранять путь файла и номер строки как evidence.
- [ ] Показывать в dry-run список прочитанных файлов.

### Source collectors

- [ ] Зафиксировать read-only contract для Git, Docker/Kubernetes, MCP и OTel metadata.
- [ ] Описать schema versioning для collector batches.
- [ ] Добавить idempotency key для повторного scan.
- [ ] Поддержать metadata-only OTel без raw production payload по умолчанию.

### Отчёт

- [ ] Выводить количество найденных агентов, tools и identities.
- [ ] Выводить findings с severity, message и evidence.
- [ ] Поддержать JSON-отчёт, пригодный для дальнейшего dashboard/API.
- [ ] Поддержать читаемый text-отчёт для терминала.

### Privacy boundary

- [ ] Добавить allowlist root paths и запрет выхода за scan root.
- [ ] Исключить secret values из parser outputs.
- [ ] Документировать, какие metadata и payloads не покидают локальную среду.

### North Star instrumentation

- [ ] Определить событие `agent_verified` и условия его засчёта в WVPA.
- [ ] Рассчитывать Time to First Verified Agent и Time to First Finding.
- [ ] Рассчитывать production-agent coverage и evidence completeness.
- [ ] Рассчитывать weekly repeat scan rate и high-risk remediation rate.

## P1 — подтверждение продуктовой ценности

### Six-month roadmap

- [ ] M1: threat model, data retention policy, `agentctl init`, local JSON report и low-fidelity flows.
- [ ] M2: GitHub/GitLab, Docker/Kubernetes и MCP sources; 10 risk rules; первый dashboard.
- [ ] M3: OTel metadata, ownership mapping, recurring scan, change detection и issue workflow.
- [ ] M4: self-hosted runner, Helm, redaction, audit log, SSO/RBAC и paid pilot package.
- [ ] M5: policy-as-code, public read API, webhooks и CI check.
- [ ] M6: stable v1, public docs, sample reports, case studies и go/iterate/pivot review.
- [ ] На каждом gate фиксировать exit criteria, а не только shipped features.

### Regional packaging

- [ ] Подготовить US/Canada developer-first CLI и cloud-first pilot.
- [ ] Подготовить Europe requirements: private deployment, audit export, data residency.
- [ ] Отдельно проверить Russia requirements: on-premise, local models, model portability.
- [ ] Не переносить pricing, buyers и sales-cycle assumptions между регионами.

### Market evidence

- [ ] Заменить агрегированный logo universe проверяемой account list.
- [ ] Для каждого target account собрать sector, size, agent signal, MCP/tool signal и предполагаемого champion.
- [ ] Зафиксировать фактические ответы интервью и recurring pain patterns.
- [ ] Проверить pilot pricing отдельно от сценарной ACV-модели.
- [ ] Пересчитать payback после получения реальных onboarding/support inputs.

### Risk engine

- [ ] Реализовать `ACP-001`: production agent без owner/team.
- [ ] Реализовать `ACP-002`: runtime agent отсутствует в source inventory.
- [ ] Реализовать `ACP-003`: один identity используется unrelated agents.
- [ ] Реализовать `ACP-004`: write/admin scope при read-only use case.
- [ ] Реализовать `ACP-005`: MCP server отсутствует в approved registry.
- [ ] Реализовать `ACP-006`: production credential в development.
- [ ] Реализовать `ACP-007`: sensitive tool без approval metadata.
- [ ] Реализовать `ACP-008`: provider/model нарушает workspace policy.
- [ ] Реализовать `ACP-009`: отсутствует disable/rollback path.
- [ ] Реализовать `ACP-010`: stale agent/identity.
- [ ] Реализовать `ACP-011`: duplicate agents одной capability.
- [ ] Реализовать `ACP-012`: schema change без owner acknowledgement.
- [ ] Для каждого finding показывать доказательство и confidence score.
- [ ] Добавить конфигурацию approved owners/providers/servers.

### Backend foundation

- [ ] Создать PostgreSQL schema для Workspace/Source/Agent/Identity/Tool/Relationship/Evidence/Finding/ScanRun.
- [ ] Добавить транзакционный commit inventory snapshot.
- [ ] Добавить Redis Streams job queue только после подтверждения async scan workload.
- [ ] Добавить signed batch ingestion и tenant isolation.
- [ ] Добавить S3-compatible evidence storage с redaction metadata.

### MCP и infrastructure collectors

- [ ] Добавить чтение распространённых MCP config formats.
- [ ] Извлекать server, transport, auth method и tool names.
- [ ] Добавить Docker Compose collector.
- [ ] Добавить Kubernetes Deployment/ServiceAccount collector.
- [ ] Не извлекать содержимое secret values.

### Remediation and lifecycle

- [ ] Добавить finding lifecycle: open, remediating, accepted-risk, closed, reopened.
- [ ] Добавить due date и accepted-risk expiry.
- [ ] Создавать GitHub/Jira/Slack actions только с явным user trigger.
- [ ] Проверять resolution на следующем scan.

### Fixtures и тесты

- [ ] Создать demo repository с 5–10 намеренными рисками.
- [ ] Добавить unit-тесты для parser’ов.
- [ ] Добавить fixture-тесты для каждого risk rule.
- [ ] Добавить smoke-тест полного `agentctl scan`.
- [ ] Проверить повторный запуск: одинаковые входы дают стабильный отчёт.

### Пользовательский результат

- [ ] Подготовить README с установкой и первым запуском.
- [ ] Показать первый полезный finding менее чем за 30 минут.
- [ ] Добавить экспорт findings в CSV.
- [ ] Добавить генерацию GitHub Issue без автоматической отправки по умолчанию.

## P2 — после подтверждения MVP

- [ ] Local SQLite adapter для offline history, если он нужен после P0.
- [ ] Web-dashboard с inventory и фильтрами.
- [ ] OpenTelemetry collector.
- [ ] GitHub App вместо локального режима.
- [ ] Jira/Slack integrations.
- [ ] PostgreSQL для командной работы.
- [ ] Self-hosted runner с outbound-only HTTPS.
- [ ] Docker Compose local deployment и Helm chart.
- [ ] OIDC authentication; SAML только при подтверждённом pilot demand.
- [ ] Отслеживание remediation status между сканированиями.
- [ ] Self-hosted deployment.

## Не включать в текущий MVP

- [ ] Runtime proxy и блокировку действий в production.
- [ ] Автоматическое изменение IAM.
- [ ] SIEM и полноценный compliance mapping.
- [ ] LLM-as-a-judge.
- [ ] Поддержку всех облаков и agent frameworks.
- [ ] Graph database.

## Definition of Done для P0

- `agentctl scan` запускается на demo repository.
- CLI работает в read-only режиме.
- Найденные сущности представлены в стабильном JSON-формате.
- Минимум три risk rule возвращают findings с file/line evidence.
- Есть автоматические тесты parser’ов, rules и полного сканирования.
