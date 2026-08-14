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

Предварительный стек: TypeScript, SQLite на этапе локального прототипа, YAML/JSON parsers. PostgreSQL и web-dashboard добавляются после подтверждения базового сценария.

## Критерий первого успеха

Пользователь получает первый полезный finding менее чем за 30 минут после запуска сканирования.

## Рыночная гипотеза

Рабочий первый ICP — SaaS/AI-native компания с production agents, несколькими tools/MCP integrations и platform/security champion. Агрегированная модель из `Regional Market Analysis of AI Agents-2.zip` используется только как сценарная гипотеза: её logo universe, ACV, penetration, win rate и unit economics требуют проверки интервью и paid pilots.

## Проверка спроса

Первый pilot: 1–3 репозитория, один Kubernetes/configuration source, до 25 агентов, read-only доступ, срок до двух недель. Целевой результат — минимум три неизвестные или materially risky связи с file/config evidence.

## Статус

Проект инициализирован. Рыночные материалы разобраны; исходный код ещё не создан.
