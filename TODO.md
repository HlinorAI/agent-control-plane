# Backlog

## Strategy alignment

- [x] Подключить product roadmap и regional strategy к проектной документации.
- [x] Зафиксировать WVPA как North Star Metric.
- [x] Выбрать США/Канаду первым beachhead-регионом.
- [x] Подключить security/compliance blueprint к проектным ограничениям.
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

- [x] Инициализировать Go-модуль с командами и строгими настройками.
- [x] Создать команду `agentctl scan <path>`.
- [x] Добавить `agentctl init` для выбора workspace и approved sources.
- [x] Добавить параметры `--dry-run`, `--format json|text` и `--output`.
- [x] Возвращать ненулевой exit code при ошибке сканирования.
- [x] Не читать значения секретов и не отправлять данные наружу.

### Контракт данных

- [x] Описать типы `Agent`, `Tool`, `Finding`, `Evidence` для первого CLI-среза.
- [x] Определить стабильные ID и базовые правила дедупликации сущностей.
- [x] Зафиксировать JSON-схему отчёта первого CLI-среза.
- [x] Добавить версию схемы отчёта.
- [x] Описать canonical relationships и типы evidence/confidence.
- [ ] Добавить OpenAPI 3.1 contract для будущего ingestion/API слоя.

### Git collector

- [x] Сканировать только разрешённый root path.
- [ ] Определять вероятные agent entrypoints по конфигурации и импортам.
- [x] Извлекать model provider/model name в первом heuristic collector.
- [x] Извлекать tool definitions и references на MCP в первом heuristic collector.
- [x] Определять environment и canonical agent name, если они явно указаны.
- [x] Сохранять путь файла и номер строки как evidence.
- [x] Показывать в dry-run список прочитанных файлов.

### Source collectors

- [ ] Зафиксировать read-only contract для Git, Docker/Kubernetes, MCP и OTel metadata.
- [ ] Описать schema versioning для collector batches.
- [ ] Добавить idempotency key для повторного scan.
- [ ] Поддержать metadata-only OTel без raw production payload по умолчанию.

### Отчёт

- [x] Выводить количество найденных агентов, tools и identities.
- [x] Выводить findings с severity, message и evidence.
- [x] Поддержать JSON-отчёт, пригодный для дальнейшего dashboard/API.
- [x] Поддержать читаемый text-отчёт для терминала.

### Privacy boundary

- [x] Добавить allowlist root paths и запрет выхода за scan root.
- [x] Исключить secret values из parser outputs.
- [x] Документировать, какие metadata и payloads не покидают локальную среду.
- [ ] Зафиксировать правило: discovery не выполняет repository hooks, scripts, prompts или agent/tool instructions.
- [ ] Добавить file/archive/AST depth/time/resource limits для parser’ов.
- [ ] Подготовить corpus для secret redaction и negative tests.

### Security P0 gate

- [ ] Проверить read-only behavior на fixture repository с malicious setup/postinstall/Dockerfile.
- [ ] Проверить, что raw secrets не попадают в JSON report и evidence.
- [ ] Не добавлять LLM в critical risk decision path.

### North Star instrumentation

- [ ] Определить событие `agent_verified` и условия его засчёта в WVPA.
- [ ] Рассчитывать Time to First Verified Agent и Time to First Finding.
- [ ] Рассчитывать production-agent coverage и evidence completeness.
- [ ] Рассчитывать weekly repeat scan rate и high-risk remediation rate.

### Security instrumentation

- [ ] Зафиксировать audit events для auth, evidence access, finding, policy и exception changes.
- [ ] Добавить negative cross-workspace authorization tests до hosted pilot.

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

- [x] Реализовать `ACP-001`: production agent без owner/team.
- [x] Реализовать `ACP-002`: runtime agent отсутствует в source inventory.
- [x] Реализовать `ACP-003`: один identity используется unrelated agents.
- [x] Реализовать `ACP-004`: write/admin scope при read-only use case.
- [x] Реализовать `ACP-005`: MCP server отсутствует в approved registry.
- [x] Реализовать `ACP-006`: production credential в development.
- [x] Реализовать `ACP-007`: sensitive tool без approval metadata.
- [x] Реализовать `ACP-008`: provider/model нарушает workspace policy.
- [x] Реализовать `ACP-009`: отсутствует disable/rollback path.
- [x] Реализовать `ACP-010`: stale agent/identity.
- [ ] Реализовать `ACP-011`: duplicate agents одной capability.
- [ ] Реализовать `ACP-012`: schema change без owner acknowledgement.
- [x] Для каждого finding показывать доказательство и confidence score.
- [x] Добавить конфигурацию approved owners/providers/servers.

### Backend foundation

- [ ] Создать PostgreSQL schema для Workspace/Source/Agent/Identity/Tool/Relationship/Evidence/Finding/ScanRun.
- [ ] Добавить транзакционный commit inventory snapshot.
- [ ] Добавить Redis Streams job queue только после подтверждения async scan workload.
- [ ] Добавить signed batch ingestion и tenant isolation.
- [ ] Добавить S3-compatible evidence storage с redaction metadata.
- [ ] Добавить signed batches, nonce, expiry и replay protection.
- [ ] Добавить object-level workspace authorization и negative cross-tenant tests.
- [ ] Добавить append-only audit events для auth, evidence, finding, policy и exception changes.

### MCP и infrastructure collectors

- [x] Добавить чтение базового MCP server/approved-registry формата.
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

- [x] Создать demo repository с намеренными рисками для `ACP-001`–`ACP-005`.
- [x] Добавить unit-тесты для parser’ов.
- [x] Добавить fixture-тесты для каждого risk rule.
- [x] Добавить smoke-тест полного `agentctl scan`.
- [x] Проверить повторный запуск: одинаковые входы дают стабильный отчёт.
- [ ] Добавить fuzz/property tests для YAML/JSON/MCP parsers.
- [ ] Добавить integration tests с PostgreSQL и connector failure paths.

### Пользовательский результат

- [x] Подготовить README с установкой и первым запуском.
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
- Первый P0 CLI-срез покрыт тестами и проверен через `go test ./...` и `go vet ./...`.
- Discovery не выполняет произвольный код и не отправляет данные наружу.
- Security-sensitive input считается untrusted data и ограничен по размеру/времени.
