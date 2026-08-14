# Backlog

## P0 — критично для первого работающего прототипа

### Product validation

- [ ] Зафиксировать one-sentence market definition и список exclusions.
- [ ] Определить минимальные признаки production agent для ICP.
- [ ] Подготовить 10–15 problem-interview вопросов.
- [ ] Составить проверяемый shortlist из 10 потенциальных design partners.
- [ ] Согласовать scope read-only diagnostic и критерий трёх полезных findings.

### Проект и CLI

- [ ] Инициализировать TypeScript-проект с package manager и строгими настройками.
- [ ] Создать команду `agentctl scan <path>`.
- [ ] Добавить параметры `--dry-run`, `--format json|text` и `--output`.
- [ ] Возвращать ненулевой exit code при ошибке сканирования.
- [ ] Не читать значения секретов и не отправлять данные наружу.

### Контракт данных

- [ ] Описать типы `Repository`, `Agent`, `Model`, `Tool`, `Identity`, `Finding`, `Evidence`.
- [ ] Определить стабильные ID и правила дедупликации сущностей.
- [ ] Зафиксировать JSON-схему отчёта.
- [ ] Добавить версию схемы отчёта.

### Git collector

- [ ] Сканировать только разрешённый root path.
- [ ] Определять вероятные agent entrypoints по конфигурации и импортам.
- [ ] Извлекать model provider/model name.
- [ ] Извлекать tool definitions и references на MCP.
- [ ] Определять repository path и environment, если они явно указаны.
- [ ] Сохранять путь файла и номер строки как evidence.
- [ ] Показывать в dry-run список прочитанных файлов.

### Отчёт

- [ ] Выводить количество найденных агентов, tools и identities.
- [ ] Выводить findings с severity, message и evidence.
- [ ] Поддержать JSON-отчёт, пригодный для дальнейшего dashboard/API.
- [ ] Поддержать читаемый text-отчёт для терминала.

### Privacy boundary

- [ ] Добавить allowlist root paths и запрет выхода за scan root.
- [ ] Исключить secret values из parser outputs.
- [ ] Документировать, какие metadata и payloads не покидают локальную среду.

## P1 — подтверждение продуктовой ценности

### Market evidence

- [ ] Заменить агрегированный logo universe проверяемой account list.
- [ ] Для каждого target account собрать sector, size, agent signal, MCP/tool signal и предполагаемого champion.
- [ ] Зафиксировать фактические ответы интервью и recurring pain patterns.
- [ ] Проверить pilot pricing отдельно от сценарной ACV-модели.
- [ ] Пересчитать payback после получения реальных onboarding/support inputs.

### Risk engine

- [ ] Реализовать правило `missing_owner`.
- [ ] Реализовать правило `shared_identity`.
- [ ] Реализовать правило `excessive_permission`.
- [ ] Реализовать правило `unknown_mcp_server`.
- [ ] Реализовать правило `untracked_production_agent`.
- [ ] Реализовать правило `cross_environment_leak`.
- [ ] Реализовать правило `unapproved_provider`.
- [ ] Для каждого finding показывать доказательство и confidence score.
- [ ] Добавить конфигурацию approved owners/providers/servers.

### MCP и infrastructure collectors

- [ ] Добавить чтение распространённых MCP config formats.
- [ ] Извлекать server, transport, auth method и tool names.
- [ ] Добавить Docker Compose collector.
- [ ] Добавить Kubernetes Deployment/ServiceAccount collector.
- [ ] Не извлекать содержимое secret values.

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

- [ ] SQLite-хранилище для истории сканирований.
- [ ] Web-dashboard с inventory и фильтрами.
- [ ] OpenTelemetry collector.
- [ ] GitHub App вместо локального режима.
- [ ] Jira/Slack integrations.
- [ ] PostgreSQL для командной работы.
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
