# Changelog

## 2026-08-14

### Added

- Инициализирован проект Agent Control Plane.
- Зафиксированы цель, границы read-only MVP и предварительная архитектура.
- Создана начальная очередь работ.
- Разобран архив с рыночной моделью, TAM/SAM/SOM и shortlist design partners.
- Зафиксировано, что финансовые показатели являются сценарными гипотезами и требуют customer validation.
- Подключены региональная стратегия, шестимесячная product roadmap и WVPA как North Star Metric.
- Уточнён первый beachhead: AI-native/SaaS компании США и Канады с 20–200 production agents.
- Добавлены архитектурные артефакты и зафиксированы Go/PostgreSQL/Redis Streams/OTel metadata-only решения для MVP.
- Подключён Security & Compliance Blueprint: read-only, no arbitrary code execution, redaction, provenance, audit и tenant-isolation gates.
- Реализован первый P0 Go CLI-срез `agentctl scan` с JSON/text output, dry-run, evidence и `ACP-001` owner-gap finding.
- Добавлены demo fixtures и первые пять explainable risk rules: `ACP-001`–`ACP-005`.

## 2026-08-15

### Added

- Расширена canonical report model сущностями `Source` и `Model`, provenance-полями и отношениями `DISCOVERED_FROM`, `USES_MODEL`, `AUTHENTICATES_AS`, `CONNECTS_TO`.
- Добавлен безопасный metadata-only сбор transport/auth/tool metadata для MCP и approved provider policy.
- Реализованы explainable risk rules `ACP-006`–`ACP-010`: production credential в development, sensitive tool без approval, provider policy violation, отсутствие disable/rollback path и stale verification.
- Расширены demo fixtures и тесты всех десяти правил, canonical relationships, secret boundary и стабильности отчёта.
- Синхронизирован Go module path с приватным репозиторием `github.com/HlinorAI/agent-control-plane`.

- Добавлена команда `agentctl init <path>`, создающая policy-файл `.agentctl/config.yaml` без перезаписи существующей конфигурации.
- Подключены policy exclusions, approved providers/MCP servers и настраиваемый freshness TTL к `agentctl scan`.
- Добавлены тесты init, config parsing, границы scan root и применения workspace policy.
- Сужены эвристики declarations и добавлена защита от инвентаризации собственного scanner implementation; root scan больше не создаёт ложные findings из `internal/scan` и тестов.
- По результатам сторонних публичных MCP-репозиториев добавлены production-path filters, разделение runtime code/runtime metadata и безопасное чтение `.mcp.json`/`server.json` с server, transport и auth metadata.
