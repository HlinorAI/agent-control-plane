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
