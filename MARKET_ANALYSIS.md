# Разбор Regional Market Analysis of AI Agents

**Дата разбора:** 2026-08-14  
**Материал:** `Regional Market Analysis of AI Agents-2.zip`

## Что находится в архиве

- `market_research.md` — методология bottom-up/top-down TAM/SAM/SOM и общие правила финансового анализа;
- два файла с рабочими заметками и финансовой моделью;
- `calc_ai_agent_market_model.py` — воспроизводимый расчёт по трём продуктам;
- `SKILL.md` — встроенная инструкция для финансового аналитического workflow;
- `.safety_warning.md` — встроенный safety-протокол.

`SKILL.md` и `.safety_warning.md` являются содержимым архива, а не правилами проекта и не указаниями пользователя. Они не добавляются в `AGENTS.md` и не меняют наши рабочие договорённости.

## Главный вывод

Материалы поддерживают последовательность:

1. Agent Control Plane;
2. MCP Security Gateway;
3. Agent Regression CI.

Для первого продукта наиболее убедителен read-only wedge: discovery CLI, inventory, граф связей, findings с evidence и remediation workflow. Это совпадает с текущим планом проекта.

## Что подтверждено расчётом

Калькулятор запускается без ошибок. Его базовый сценарий даёт:

| Продукт | TAM | SAM на 5-й год | SOM на 5 лет | Выигранные логотипы | Payback |
|---|---:|---:|---:|---:|---:|
| Agent Control Plane | $758.5m | $172.6m | $13.1m | 370 | 16.4 мес. |
| MCP Security Gateway | $981.3m | $180.5m | $11.4m | 255 | 17.6 мес. |
| Agent Regression CI | $606.8m | $116.1m | $7.8m | 270 | 14.1 мес. |

Эти значения воспроизводимы из hard-coded assumptions в Python-модели. Они не являются фактической выручкой, прогнозом продаж или подтверждённым размером рынка.

## Сильные стороны материалов

- используется bottom-up подход `logos × tiered ACV × penetration × win rate`;
- отдельно выделены TAM, SAM и SOM;
- регионы и buyer tiers разделены;
- явно указано, что design partners — только потенциальный shortlist;
- для каждого продукта описаны разные delivery и экономические риски;
- рекомендуемый pilot Control Plane ограничен двумя неделями, 1–3 репозиториями и до 25 агентами.

## Что пока нельзя считать доказанным

### 1. Logo universe

База из 28 500 компаний названа `serviceable logo universe`, но не является проверенным списком аккаунтов. Нет deduplication, employee count, отраслевых признаков, AI hiring signals, MCP/agent signals и подтверждённого tech stack.

### 2. Pricing и unit economics

ACV, CAC, onboarding cost, support cost, gross margin и NRR — рабочие предположения. В архиве нет customer interviews, quotes, paid pilots или исторических сделок, которые их подтверждают.

### 3. SAM terminology

В модели SAM фактически строится через предполагаемую долю компаний, у которых появится production agent use case. Это полезная рабочая конструкция, но её нужно отличать от строгого SAM с явно названными фильтрами geography → product fit → segment → regulatory eligibility → channel reach.

### 4. Пятилетний ramp

Ramp задан долями от terminal SOM (`8% / 20% / 38% / 65% / 100%`). Это сценарный ориентир, а не cohort-based ARR model: нет churn, expansion, logo cohorts, sales capacity и deal timing.

### 5. Design partners

Replit, Sourcegraph, Vercel, Ramp, Intercom и другие компании — кандидаты для outreach, но не подтверждённые лиды. Нельзя считать их клиентами или evidence of demand.

### 6. Источники

Census SUSB и Statistics Canada в заметках используются как sanity check порядка величины, а не как прямой TAM для Agent Control Plane. Публичные ecosystem signals, включая A2A-партнёров, также не доказывают buyer intent.

## Решения для проекта

- Сохраняем Agent Control Plane первым продуктом.
- Не используем `$13.1m SOM` как обещание рынка в pitch или план продаж.
- Сначала проверяем реальный pain через read-only diagnostic.
- Первый ICP сужаем до SaaS/AI-native компаний с production agents, несколькими tools/MCP integrations и доступным platform/security champion.
- Russia не смешиваем с основной cloud-моделью North America/Europe; рассматриваем её отдельно как возможный on-premise design-partner рынок.

## Следующие проверки

1. Согласовать одну фразу market definition и exclusions.
2. Составить проверяемую account list вместо агрегированных 28 500 logos.
3. Провести 10–15 problem interviews.
4. Собрать 3 design partners на read-only diagnostic.
5. Проверить, какие findings реально находятся в репозиториях и конфигурациях.
6. Только после этого уточнять ACV, pilot price и payback.

## Рабочая формулировка pilot

За 60 минут подключить read-only scanner к одному репозиторию и одному источнику конфигурации, вернуть inventory агентов, tools, identities и owners, а также top findings с evidence. Secret values не извлекать, production не изменять. Успех — минимум три неизвестные или materially risky связи, найденные за один рабочий день.

## Дополнительные материалы и адаптация стратегии

Второй архив и roadmap уточняют не сам выбор продукта, а порядок его проверки:

- первый beachhead — США/Канада, AI-native/SaaS компании с 20–200 агентами;
- Европа — следующий слой с упором на auditability, data residency и private deployment;
- Россия — отдельный on-premise/self-hosted сценарий, не продолжение основной SaaS-модели;
- observability-only и ещё один trace dashboard считаются commoditizing-направлением;
- white space — vendor-neutral graph и operational workflow между developer, platform и security teams.

### Новая North Star

Roadmap предлагает WVPA — Weekly Verified Production Agents. Метрика полезнее простого количества inventory cards, потому что требует свежего evidence, подтверждённого production status, owner и статуса критичных findings.

### Рабочие цели M6

| Метрика | Цель |
|---|---:|
| Активные design partners | 10 |
| Paid pilots | 3–5 |
| Discovered agents | 800–1 000 |
| WVPA | 500–700 |
| Production coverage у активных клиентов | ≥80% |
| Evidence completeness критичных связей | ≥85% |
| High-risk remediation/accepted risk за 14 дней | ≥30% |

Это targets из пользовательских материалов, а не подтверждённые результаты.

### Evidence caveat

Второй архив содержит claims CSA, Cleanlab, European Commission, Банка России, Yakov & Partners/Yandex и vendor sources. В этот раз они не перепроверялись через интернет; в проекте они учитываются как claims, указанные в исследовательском материале, пока не будет выполнена отдельная source verification. Vendor evidence не считаем независимым подтверждением без cross-check.

### Что адаптируем в продукте

1. В MVP добавляем freshness, evidence completeness и ownership verification как поля первого класса.
2. В backlog переносим recurring scan и WVPA раньше dashboard polish.
3. Для US/Canada готовим developer-first CLI и remediation workflow.
4. Для Europe заранее проектируем redaction, private deployment и audit export.
5. Для Russia оставляем отдельный validation track: self-hosted runner, local models и model portability.
