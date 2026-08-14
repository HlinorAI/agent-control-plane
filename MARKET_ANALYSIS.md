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

