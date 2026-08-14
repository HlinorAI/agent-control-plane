# Agent Control Plane

## Цель

Создать read-only инструмент, который обнаруживает AI-агентов во внутренних репозиториях и конфигурациях, показывает их связи с моделями, identities и tools, а также находит подтверждённые permission и ownership gaps.

## Первый MVP

- локальный CLI `agentctl scan`;
- сканирование Git-репозитория, MCP-конфигураций и Docker/Kubernetes-манифестов;
- inventory агентов;
- граф связей `Agent → Identity → Tool → Data`;
- до 10 понятных risk rules;
- evidence для каждого finding;
- JSON/CSV-отчёт и экспорт findings в GitHub Issues.

## Ограничения MVP

Инструмент работает только в read-only режиме. В первый этап не входят runtime proxy, автоматическое изменение IAM, полноценный compliance-модуль, SIEM и поддержка всех облачных провайдеров.

## Предварительная архитектура

```text
CLI
  → collectors (Git, MCP, Docker/Kubernetes)
  → normalizer/entity resolver
  → inventory + findings
  → JSON/CSV report
```

Целевая архитектура подробно описана в `Архитектура MVP Agent Control Plane.txt`, а схемы сохранены в `agent_control_plane_architecture.mmd` и `agent_control_plane_architecture.d2`.

Архитектурные решения MVP:

- Go для `agentctl`, self-hosted runner, parsers и API;
- PostgreSQL для inventory, relationships, findings и scan history;
- Redis Streams для асинхронных scan jobs на hosted/self-hosted backend;
- S3-compatible storage для redacted evidence artifacts;
- React + TypeScript для UI;
- OpenTelemetry metadata-only по умолчанию;
- Docker Compose для local pilot и Helm для Kubernetes;
- relationships в PostgreSQL вместо graph database до появления доказанной потребности.

Для P0 допускается локальный JSON output без backend. Это позволяет проверить scanner и evidence contract до запуска ingestion API и очереди.

Целевой масштаб MVP: 10 design partners, 500–1 000 discovered agents, 25–50 workspaces и до 10 млн metadata/evidence events в месяц. Это target architecture, а не обязательный объём первого прототипа.

## Security baseline

`Security & Compliance Blueprint для Agent Control Plane.md` подключён как обязательная инженерная граница MVP. Discovery path работает read-only и не запускает чужой agent code, prompts, tool responses или repository hooks. Raw secrets и полные production payloads не сохраняются по умолчанию; OTel — metadata-only. Все relationships и findings должны иметь provenance, hash/timestamp и confidence, а критичные решения принимаются детерминированными rules, не LLM.

До design-partner pilot обязательны: secret-redaction tests, parser resource limits, cross-workspace authorization tests, audit events для sensitive actions, documented retention/deletion behavior и outbound-only self-hosted runner.

## Критерий первого успеха

Пользователь получает первый полезный finding менее чем за 30 минут после запуска сканирования.

## Рыночная гипотеза

Рабочий первый ICP — SaaS/AI-native компания с production agents, несколькими tools/MCP integrations и platform/security champion. Агрегированная модель из `Regional Market Analysis of AI Agents-2.zip` используется только как сценарная гипотеза: её logo universe, ACV, penetration, win rate и unit economics требуют проверки интервью и paid pilots.

## Стратегия и методология

`regional-ai-agent-product-strategy.skill` подключён как project-specific методологический материал. Он задаёт порядок проверки: real users → real problems → workarounds → existing products → white space → MVP → pricing → design partners → roadmap. Он не переопределяет пользовательские и проектные правила.

Исследование ведём по регионам отдельно: сначала США/Канада, затем Европа, затем Россия. Не смешиваем evidence, buyer, pricing и delivery assumptions до сравнительного анализа.

Региональные слои продукта:

- США/Канада: runtime security, ownership, permissions и cost/reliability для AI-native/SaaS;
- Европа: auditability, data residency, governance evidence и private deployment;
- Россия: self-hosted/on-premise, model portability и heterogeneous infrastructure.

## North Star Metric

**WVPA (Weekly Verified Production Agents)** — количество production-агентов со свежим evidence-backed статусом: подтверждены source, environment, owner/team, критичные model → identity → tool/data relationships и статус high-risk findings.

На шестой месяц рабочая цель: 10 активных design partners, 3–5 paid pilots, 500–700 WVPA, не менее 80% production coverage у активных клиентов и не менее 85% evidence completeness для критичных связей.

## Шестимесячные продуктовые gates

- M1: подтверждены 3 повторяющихся pain patterns и 5 qualified design partners;
- M2: scan работает на 5 реальных аккаунтах, TTFV менее 30 минут;
- M3: recurring scan и ownership/identity graph дают повторную ценность;
- M4: self-hosted runner, redaction, RBAC и security review готовы для paid pilot;
- M5: клиенты используют policy checks и weekly scans;
- M6: есть repeatable onboarding, 3 referenceable case studies и основания для решения go/iterate/pivot.

## Проверка спроса

Первый pilot: 1–3 репозитория, один Kubernetes/configuration source, до 25 агентов, read-only доступ, срок до двух недель. Целевой результат — минимум три неизвестные или materially risky связи с file/config evidence.

## Статус

Проект инициализирован. Рыночные материалы, roadmap, архитектура и security blueprint подключены. Первый P0-срез Go CLI, demo fixtures и правила `ACP-001`–`ACP-005` реализованы; следующий этап — расширение collectors и canonical data model.
