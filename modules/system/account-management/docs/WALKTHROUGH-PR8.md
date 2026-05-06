# AM PR #8 — Разбор реализации (для джуниоров)

**PR**: https://github.com/diffora/cyberfabric-core/pull/8
**Branch**: `am/03-integrity-and-bootstrap`
**Что доехало в этот PR**: три большие фичи в модуле `account-management` (`AM`), плюс инфраструктура и тесты к ним.

Этот документ — пошаговый разбор «что сделано и почему» для разработчика, который видит этот код впервые. Каждый раздел начинается с «зачем оно нужно», потом идёт алгоритм по шагам, в конце — ссылки на конкретные файлы.

---

## Содержание

1. [Глоссарий (термины, без которых дальше непонятно)](#1-глоссарий)
2. [Что в PR одной картинкой](#2-что-в-pr-одной-картинкой)
3. [Часть 1: Hierarchy integrity check (проверка целостности дерева тенантов)](#3-часть-1-hierarchy-integrity-check)
4. [Часть 2: Auto-repair (автоматическая починка closure-таблицы)](#4-часть-2-auto-repair)
5. [Часть 3: Platform-bootstrap saga (создание корневого тенанта при старте)](#5-часть-3-platform-bootstrap-saga)
6. [Часть 4: Single-flight gate (`integrity_check_runs`)](#6-часть-4-single-flight-gate)
7. [Часть 5: Тесты — что где живёт](#7-часть-5-тесты)
8. [Часть 6: Что НЕ сделано и почему](#8-часть-6-что-не-сделано-и-почему)

---

## 1. Глоссарий

Термины встречаются на каждом шагу, поэтому сначала база.

| Термин | Что значит |
|---|---|
| **Тенант** | Узел в дереве организаций. Каждый клиент платформы — отдельный тенант. У root-тенанта нет родителя (`parent_id IS NULL`). |
| **`tenants`** | Основная таблица. Колонки: `id`, `parent_id`, `name`, `status`, `self_managed`, `depth`, timestamps. |
| **Closure-таблица** (`tenant_closure`) | Таблица из пар `(ancestor_id, descendant_id)`: для каждого узла дерева и каждого его предка (включая самого себя) — отдельная строка. Альтернатива рекурсивным CTE: запрос «все потомки X» становится простым `WHERE ancestor_id = X` вместо рекурсии. |
| **SecureORM** | Обёртка над `sea_orm` в `modkit-db`, которая принудительно подставляет `AccessScope` в каждый SQL. Гарантирует, что код не сделает unscoped read случайно. |
| **`AccessScope`** | Описание «кому какие тенанты разрешено видеть/менять». `AccessScope::allow_all()` — системный bypass, используется во внутренних reaper'ах / интегриты-проверках. |
| **Saga** | Последовательность шагов в распределённой системе. У каждого шага может быть compensating action (откат). Если шаг 3 упал — мы делаем откат шагов 1-2 явными compensating-действиями, а не транзакцией БД. |
| **Idempotency** | Свойство операции: повторный вызов не меняет результат. Bootstrap при рестарте платформы должен быть идемпотентным — если корневой тенант уже создан, не создавать второй. |
| **Single-flight gate** | Механизм: «в один момент времени только один воркер делает X». В нашем случае — только один воркер бежит integrity check для всего модуля. |
| **TTL** (time-to-live) | Срок «свежести» записи. После TTL запись считается stale и может быть переиспользована. |
| **Stale-sweep** | Очистка просроченных (stale) записей. У нас — удаление застрявших lock-row старше `MAX_LOCK_AGE = 1h`. |
| **Reaper** | Background-задача, которая «пожирает» застрявшие сущности. У AM есть reaper для `Provisioning` тенантов: если `provision_tenant` упал и оставил row в `Provisioning` дольше чем `provisioning-timeout`, reaper его компенсирует. |
| **Compensating action** | Действие, которое отменяет результат предыдущего шага саги. Пример: если шаг 2 (создать тенанта в IdP) прошёл, а шаг 3 (активировать локально) упал → нужна compensating action «удалить тенанта из IdP». |
| **Fence-token** | Монотонно растущий токен, который выдаётся вместе с лизом. Любая запись фенсится: «я владею ресурсом с токеном N, разрешите запись только если в БД ещё N». Защищает от ситуации, когда мы потеряли лиз, но не знаем об этом. |
| **IdP** (Identity Provider) | Внешняя система управления идентичностью (AD/LDAP/SAML/OIDC). AM делегирует ей создание пользователей в новом тенанте через `provision_tenant`. |
| **Classifier** | Функция, которая по snapshot'у `(tenants, tenant_closure)` находит конкретный тип нарушения целостности и возвращает список найденных «кривых» строк. У нас 8 классификаторов, эмитящих 10 категорий. |

---

## 2. Что в PR одной картинкой

```
┌─────────────────────────────────────────────────────────────────┐
│                          AM PR #8                                │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Фича 1: Hierarchy integrity check (проверка)              │ │
│  │  - 8 Rust-классификаторов поверх snapshot                  │ │
│  │  - 10 категорий нарушений                                  │ │
│  │  - Single-flight gate                                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Фича 2: Auto-repair (починка)                             │ │
│  │  - 3-проходный планировщик                                  │ │
│  │  - Periodic loop (тикает раз в N минут)                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Фича 3: Platform-bootstrap saga                            │ │
│  │  - Создание root-тенанта при первом старте                  │ │
│  │  - State machine: 8 состояний                                │ │
│  │  - Multi-replica coordination через unique-index            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Плюс: тесты (lib + SQLite + Postgres testcontainers),          │
│        infrastructure (lock.rs, classifiers/, repair.rs,         │
│        snapshot.rs, loader.rs).                                  │
└─────────────────────────────────────────────────────────────────┘
```

72 файла, 12500+ строк добавлено / 200+ удалено.

---

## 3. Часть 1: Hierarchy integrity check

### 3.1 Зачем нужно

В `tenants` + `tenant_closure` могут появиться **аномалии**:

- **Orphan**: у тенанта `parent_id` указывает на несуществующего родителя.
- **Cycle**: A → B → C → A (цикл в дереве).
- **Depth mismatch**: `tenants.depth = 5`, а реальная глубина (по `parent_id` walk'у) = 3.
- **Missing self-row в closure**: `tenant_closure` обязан содержать `(id, id)` для каждого SDK-видимого тенанта. Если строки нет — closure неполный.
- **Closure coverage gap**: `parent_id` chain даёт `(A, D)` пару, а в `tenant_closure` её нет.
- **Stale closure row**: `tenant_closure` содержит строку, которой не должно быть (parent_id walk её не выводит).
- **Barrier divergence**: `tenant_closure.barrier` (флаг self-managed boundary) расходится с реальным состоянием по `parent_id` walk'у.
- **Status divergence**: `tenant_closure.descendant_status` не совпадает с `tenants.status` по тому же descendant_id.

Эти аномалии не должны возникать в норме — но могут появиться из-за бага в коде, ручного SQL'а в проде, race condition'а между миграциями, и т.д. Нужен механизм, чтобы:
1. **Регулярно** проверять целостность.
2. **Эмитить метрики** для алертов.
3. **Чинить** то, что починить можно (часть категорий derivable).

### 3.2 Старая реализация и почему её заменили

Раньше проверка целостности была написана на raw SQL — большие запросы с подзапросами и `JOIN`'ами. Проблемы:
- Сложно поддерживать (любая правка дерева требует править 8 SQL-запросов).
- Cross-backend параcity ломается на нюансах диалектов (PostgreSQL vs SQLite).
- Тесты на raw SQL хрупкие.

В этом PR raw-SQL путь **заменён** на Rust-side classifier pipeline.

### 3.3 Алгоритм integrity check (по шагам)

**Запуск**: `TenantService::check_hierarchy_integrity()` (internal SDK method, `pub(crate)`).

```
ШАГ 1: ACQUIRE GATE
  - Открыть короткую committed-транзакцию
  - INSERT в `integrity_check_runs` (id=1) — singleton-row
  - Если PK conflict (другой воркер уже работает) → вернуть DomainError::IntegrityCheckInProgress
    (на boundary конвертится в HTTP 429)
  - Перед INSERT: sweep stale rows (started_at < now - 1h) — на случай крэша
  - Commit acquire-tx; row становится видна другим контендерам

ШАГ 2: SNAPSHOT TX
  - Открыть отдельную транзакцию с REPEATABLE READ изоляцией (PG)
    или SERIALIZABLE (SQLite — у него нет REPEATABLE READ, маппинг в modkit-db)
  - Загрузить ВСЕ tenants и tenant_closure в память через SecureORM
  - SDK-видимость фильтруется: provisioning тенанты НЕ попадают в snapshot
    (по ADR-0007 — provisioning rows не имеют closure-rows by construction)

ШАГ 3: ПРОГНАТЬ 8 КЛАССИФИКАТОРОВ
  - Каждый — pure Rust функция, бежит синхронно над загруженным snapshot
  - Не делает DB-вызовов
  - Возвращает Vec<Violation> со всеми найденными кривыми строками

ШАГ 4: RELEASE GATE
  - Отдельная committed-транзакция: DELETE из integrity_check_runs
  - Если DELETE 0 строк → significant: нашу запись съел stale-sweep другого воркера
    → emit `evicted_by_sweep` warn-log (наблюдается через tracing)

ШАГ 5: AGGREGATE + METRICS
  - Сервис складывает Vec<Violation>'ы в IntegrityReport (per-category)
  - Эмитит метрику `am.hierarchy_integrity_violations` с label'ом category
```

### 3.4 8 классификаторов

Все живут в [`infra/storage/integrity/classifiers/`](account-management/src/infra/storage/integrity/classifiers/).

| Классификатор | Файл | Что находит | Категория(и) |
|---|---|---|---|
| `orphan` | [orphan.rs](account-management/src/infra/storage/integrity/classifiers/orphan.rs) | `parent_id` указывает либо на несуществующего родителя (orphan), либо на родителя в `Deleted` статусе (broken parent ref). | `orphaned_child`, `broken_parent_reference` |
| `cycle` | [cycle.rs](account-management/src/infra/storage/integrity/classifiers/cycle.rs) | DFS с seen-set'ом по `parent_id`. Тенант, достижимый сам из себя через `parent_id` chain — цикл. | `cycle_detected` |
| `depth` | [depth.rs](account-management/src/infra/storage/integrity/classifiers/depth.rs) | `tenants.depth` отличается от глубины, выведенной walk'ом по `parent_id`. | `depth_mismatch` |
| `self_row` | [self_row.rs](account-management/src/infra/storage/integrity/classifiers/self_row.rs) | SDK-видимый тенант без `(id, id)` строки в closure. | `missing_closure_self_row` |
| `strict_ancestor` | [strict_ancestor.rs](account-management/src/infra/storage/integrity/classifiers/strict_ancestor.rs) | Строки `(A, D)` с `A != D`, выведенные `parent_id` walk'ом, но отсутствующие в `tenant_closure`. | `closure_coverage_gap` |
| `extra_edge` | [extra_edge.rs](account-management/src/infra/storage/integrity/classifiers/extra_edge.rs) | Строки `(A, D)` в `tenant_closure`, **не** выводимые `parent_id` walk'ом (orphan closure rows). | `stale_closure_row` |
| `root` | [root.rs](account-management/src/infra/storage/integrity/classifiers/root.rs) | Количество тенантов с `parent_id IS NULL` ≠ 1. | `root_count_anomaly` |
| `barrier` | [barrier.rs](account-management/src/infra/storage/integrity/classifiers/barrier.rs) | Один проход, две проверки: (1) `tenant_closure.barrier` расходится с walk'ом по `self_managed`; (2) `tenant_closure.descendant_status` расходится с `tenants.status`. | `barrier_column_divergence`, `descendant_status_divergence` |

**Важно**: 8 классификаторов → 10 категорий. Два эмитят по 2 категории (`orphan` и `barrier`). Это намеренно: один проход дешевле двух, но категории нужны разные для дашбордов.

### 3.5 Где жить snapshot'у в памяти

Полный snapshot грузится в память через [`loader.rs`](account-management/src/infra/storage/integrity/loader.rs):
```rust
pub struct Snapshot {
    pub tenants: Vec<TenantModel>,
    pub closure: Vec<ClosureRow>,
}
```

Memory footprint = `O(tenants + closure_rows + violations)`. На дереве в 100k тенантов глубиной 10 это ~1M closure_rows (дерево глубины d даёт `d+1` closure rows на тенанта). Плюс violations в худшем случае — ну и пусть. AM — модуль управления оргструктурой, не транзакционный hot path.

---

## 4. Часть 2: Auto-repair

### 4.1 Зачем нужно

Часть категорий **derivable** — то есть мы знаем «правильный» вид closure'а из `tenants.parent_id` chain'а. Если в `tenant_closure` чего-то не хватает или есть лишнее — можно восстановить ровно то, что выводится из `parent_id`.

**Не derivable**: cycle (нельзя «починить» цикл автоматически — нужно оператору решать), orphan (родителя нет — куда подвешивать?), depth mismatch (требует rewrite `tenants.depth` — это outside repair scope).

**Derivable** (что repair умеет починить):
- `missing_closure_self_row` → INSERT строки `(id, id)`.
- `closure_coverage_gap` → INSERT недостающих strict-ancestor строк.
- `stale_closure_row` → DELETE лишних строк.
- `barrier_column_divergence` → UPDATE `tenant_closure.barrier` на правильное значение.
- `descendant_status_divergence` → UPDATE `tenant_closure.descendant_status` на `tenants.status`.

### 4.2 Алгоритм repair (по шагам)

**Запуск**: `TenantRepo::repair_derivable_closure_violations()`. Зовётся из periodic loop в [`integrity_check/service.rs`](account-management/src/domain/integrity_check/service.rs) (раз в N минут — конфиг).

Алгоритм — **3 прохода** над snapshot'ом ([repair.rs](account-management/src/infra/storage/integrity/repair.rs)):

```
ВХОД: snapshot = (tenants, tenant_closure)

PASS 1: ПОСТРОИТЬ EXPECTED CLOSURE
  - HashMap<(ancestor_id, descendant_id), ExpectedRow> expected
  - Для каждого SDK-видимого тенанта T:
    - Если T в cycle (определяется заранее) или у T orphan-цепочка вверх → пропустить (не derivable)
    - Иначе: walk по parent_id от T до корня
      - На каждом шаге i: добавить (ancestor_i, T) в expected с правильным barrier и descendant_status
    - Также добавить (T, T) self-row

PASS 2: НАЙТИ DELETES
  - HashMap<(ancestor, descendant), bool> actual_keyed (из загруженного closure)
  - Для каждой строки в actual_keyed:
    - Если ключа нет в expected → это stale closure row → добавить в deletes
    - (Корректные cross-boundary edge cases отбрасываются на уровне expected — Pass 1 учитывает)

PASS 3: ЭМИТ INSERT-ОВ И UPDATE-ОВ
  - Для каждой expected_row, отсутствующей в actual_keyed → INSERT
  - Для каждой строки совпадающей по (a, d) но с расхождением в barrier/status → UPDATE

ВЫХОД: RepairReport (per-category counters: repaired_inserts, repaired_deletes, repaired_updates)
```

**Почему три прохода, а не один**: алгоритмически проще и надёжнее. Pass 1 строит «правильную картину», pass 2/3 сравнивают с реальной. Один-проход смешивал бы построение и diff, что трудно тестировать.

### 4.3 Periodic loop

[`integrity_check/service.rs`](account-management/src/domain/integrity_check/service.rs) запускает `IntegrityCheckLoop`:
```
1. Sleep `check_interval_secs` секунд.
2. Acquire single-flight gate.
3. Run integrity check → получить Vec<Violation>.
4. Если violations не пустой и `repair_enabled = true` → run repair.
5. Release gate.
6. Goto 1.
```

В тестах `check_interval_secs` ставят в 0 — loop тикает сразу.

---

## 5. Часть 3: Platform-bootstrap saga

### 5.1 Зачем нужно

При **первом старте платформы** (`module::init` в `cyberfabric-core`) или **после крэша** надо создать корневой тенант.

Усложнения:
- **Два шага в разных системах**: создать row в нашей БД (`tenants`) и создать соответствующего root-тенанта в IdP (внешний `provision_tenant` round-trip).
- **Multi-replica deployment**: несколько replic'ов AM могут стартовать одновременно и конкурировать за создание root'а. Только один должен победить.
- **Crash recovery**: если кто-то упал посреди — следующий рестарт должен либо завершить начатое, либо откатить.
- **Идемпотентность**: при простом рестарте (без аномалий) bootstrap должен быть no-op — root уже есть, ничего не делаем.

### 5.2 Состояние корневого тенанта (4 варианта)

`BootstrapClassification`:
- `NoRoot` — row не существует. Нужно создавать.
- `ActiveRootExists` — row уже есть и `status = Active`. **Skip-path**: bootstrap идемпотентно завершается с `Ok`.
- `ProvisioningRootResume(existing)` — row есть, `status = Provisioning`. Кто-то начал, но не закончил. Дальше — зависит от возраста.
- `InvariantViolation { observed_status }` — row есть в `Suspended` или `Deleted`. **Невозможное состояние** для root'а. Fail-fast → `Internal`.

### 5.3 State machine — 8 состояний

После refactor'а в этой сессии saga реализована как явный state machine ([service.rs](account-management/src/domain/bootstrap/service.rs)):

```
enum BootstrapState {
    InitialClassify,            // Начало: классифицировать row
    InitialPreflightAndWait,    // NoRoot path: проверить tenant-type schema + дождаться IdP
    LoopClassify,                // Внутри retry-loop'а: re-классифицировать
    TakeoverPreflightAndWait,   // Resume → NoRoot transition: те же checks но на take-over
    Insert,                      // INSERT Provisioning row в tenants
    Finalize { provisioning_root: TenantModel },  // Зов IdP::provision_tenant + activate_tenant
    Sleep { reason: SleepReason },  // backoff + return to LoopClassify
    Terminal(Result<TenantModel, DomainError>),  // Финальный результат
}
```

**Driver loop** в `run()`:
```rust
let mut state = BootstrapState::InitialClassify;
loop {
    state = self.step(state, &mut ctx).await;  // step выполняет IO и возвращает следующее состояние
    if let BootstrapState::Terminal(result) = state {
        return result;
    }
}
```

`step()` — диспетчер на 7 step-функций, по одной на каждое не-terminal состояние.

### 5.4 Алгоритм для green-path (NoRoot → Active)

Пошагово, что происходит при «честном первом старте» (БД пустая, IdP отвечает):

```
ВХОД: пустая БД, IdP здоров

ШАГ 1: InitialClassify
  - find_by_id(root_id) → None → cls = NoRoot
  - state := InitialPreflightAndWait

ШАГ 2: InitialPreflightAndWait
  - preflight_root_tenant_type():
    - Запросить TypesRegistryClient.get_type_schema(cfg.root_tenant_type)
    - Проверить что schema разрешает быть root'ом (нет родителя в allowed_parent_types)
    - Если нет — fail-fast Internal (миссconfig)
  - wait_for_idp_availability():
    - Опросить idp.check_availability()
    - Если Ok — продолжаем
    - Если Err — sleep + retry до deadline
  - state := LoopClassify

ШАГ 3: LoopClassify
  - Повторно classify (на случай если за время preflight кто-то опередил)
  - cls = NoRoot, pending_takeover_precheck = false → state := Insert

ШАГ 4: Insert
  - insert_root_provisioning(scope):
    - INSERT row с status=Provisioning, parent_id=NULL, depth=0, claimed_by=NULL
    - Защищён ux_tenants_single_root unique-index'ом
    - Если AlreadyExists (peer выиграл) — увеличить streak, sleep, LoopClassify
    - Если Ok — state := Finalize { provisioning_root: inserted }

ШАГ 5: Finalize { provisioning_root }
  - Внутри finalize():
    - Вызвать idp.provision_tenant(req) внутри tokio::time::timeout_at(deadline, ...)
    - На Ok(result):
      - handle_provision_success:
        - activate_tenant(): status: Provisioning → Active, материализовать closure self-row
      - state := Terminal(Ok(active_root))
    - На Err(CleanFailure):
      - compensate (DELETE provisioning row), вернуть IdpUnavailable
      - retry-loop: state := Sleep(IdpRetryOnFinalize)
    - На Err(Ambiguous):
      - НЕ компенсируем (vendor мог успеть создать tenant)
      - state := Terminal(Err(Internal))  — оператор разбирает
    - На Err(_elapsed):
      - НЕ компенсируем (timeout в timeout_at не доказывает что vendor не создал)
      - state := Terminal(Err(IdpUnavailable))

ШАГ 6: Terminal(Ok(active_root))
  - run() возвращает Ok(active_root)
```

### 5.5 Алгоритм для resume-and-takeover (Resume → NoRoot → Active)

Сценарий: peer-replica начал bootstrap (создал Provisioning row), но крэшнулся. Reaper подобрал и компенсировал. Мы стартуем после.

```
ВХОД: Provisioning row существует, но peer уже мёртв
       Reaper в процессе компенсации (между нашими classify-итерациями)

ШАГ 1: InitialClassify
  - find_by_id → Provisioning row, age = X
  - Если X > stuck_threshold (= 2 × idp_wait_timeout_secs): defer-to-reaper, Terminal(Err)
  - Если X ≤ stuck_threshold: peer возможно ещё работает
    - pending_takeover_precheck := true
    - state := LoopClassify

ШАГ 2: LoopClassify
  - find_by_id → Provisioning (peer ещё не закончил)
  - already_exists_streak := 0 (счётчик другой ветки)
  - Не deadline'нулись → emit "provisioning_wait, retry" metric → Sleep(PeerInProgress)

ШАГ 3: Sleep(PeerInProgress)
  - tokio::time::sleep(backoff)
  - backoff *= 2 (exponential)
  - state := LoopClassify

ШАГ 4: LoopClassify (вторая итерация)
  - Тем временем reaper удалил row
  - find_by_id → None → cls = NoRoot
  - pending_takeover_precheck = true → state := TakeoverPreflightAndWait

ШАГ 5: TakeoverPreflightAndWait
  - Те же проверки, что в InitialPreflightAndWait
    (preflight + IdP availability) — но «за take-over»
  - pending_takeover_precheck := false (флипаем чтобы не повторять)
  - state := Insert

ШАГ 6: Insert
  - insert_root_provisioning → Ok
  - state := Finalize

ШАГ 7-8: Finalize → Terminal(Ok(active_root))
```

Ключевое: флаг `pending_takeover_precheck` ставится в Step 1 и снимается в Step 5. Если на step 4 LoopClassify обнаружил `NoRoot` напрямую (БЕЗ предшествующего Resume) — флаг был бы `false`, и step 5 был бы пропущен. Так гарантируется, что preflight + wait делается **ровно один раз** за `run()`.

### 5.6 Compensation contract (load-bearing!)

Это самое критичное место saga. Разные ошибки IdP приводят к разным compensating action'ам:

| Ошибка от `idp.provision_tenant` | Что значит | Что делает saga |
|---|---|---|
| `Ok(result)` | Vendor создал тенанта успешно | Activate, return Ok |
| `Err(CleanFailure)` | Vendor явно сказал «не получилось, ничего не создал» | Удалить локальную row → retry / IdpUnavailable |
| `Err(Ambiguous)` | Vendor вернул сетевую ошибку: непонятно создал или нет | **НЕ удалять** локальную row → reaper разберёт. Return Internal. |
| `Err(UnsupportedOperation)` | Vendor не поддерживает provision (плагин-заглушка) | Удалить локальную row → return UnsupportedOperation |
| `Err(_elapsed)` (timeout) | `timeout_at` сработал | **НЕ удалять** локальную row (timeout не доказывает что vendor не создал) → return IdpUnavailable. Reaper разберёт. |

**Почему `Ambiguous` и timeout не компенсируем**: если vendor получил наш request и успел создать tenant, а потом сеть отвалилась → vendor'ская сторона имеет orphan'ного root-тенанта, AM-сторона ничего не знает. Если мы DELETE'нем local row и retry-нем, то снова дёрнем `provision_tenant` — vendor создаст **второго** root'а. Получится дубликат на vendor-стороне, который мы не сможем подобрать.

Поэтому policy: **timeout = ambiguous → реaper разберётся**. Reaper позже подберёт row, попробует `deprovision_tenant` (идемпотентен — vendor либо удалит существующий, либо скажет «уже нет», в любом случае состояние сходится).

### 5.7 Multi-replica coordination

Координация между replic'ами при первом старте идёт **без отдельного coordinator-сервиса**, через **DB-нативные примитивы**:

**Primitive 1: `ux_tenants_single_root` partial unique index**
```sql
CREATE UNIQUE INDEX ux_tenants_single_root
  ON tenants (parent_id) WHERE parent_id IS NULL;
```
Гарантирует на уровне БД: **не более одной строки** с `parent_id IS NULL`. Две replic'и одновременно делают INSERT — одна выигрывает atomic-ом, вторая получает `AlreadyExists`. Это **сильнее**, чем lease в modkit-coord — нет TTL-окна, нет fence-токенов, atomic by construction.

**Primitive 2: `already_exists_streak` cap (= 3)**
Если local классификатор всегда возвращает `NoRoot` (по `cfg.root_id`), а DB всегда возвращает `AlreadyExists` (есть другой root с другим `id`) — это oscillation, который зациклит retry-loop. Cap converts in `MAX_ALREADY_EXISTS_STREAK = 3` итераций и эскалирует в `Internal` ("config drift" — оператор поправит).

**Primitive 3: `claimed_by` / `claimed_at` на `tenants`**
Используется reaper'ом. Когда reaper берёт стрижку, он claim'ит row. Saga, попытавшись compensate row, у которого claim не совпадает (peer reaper его держит), получает Conflict — и swallow'ит ошибку (это not-our-row scenario).

**Primitive 4: `stuck_threshold = 2 × idp_wait_timeout_secs`**
Saga timeout'ится через `idp_wait_timeout_secs`. Reaper считает row stuck через `2 × idp_wait_timeout_secs`. Этот зазор гарантирует: peer всегда успевает либо завершить, либо саму-таймнуть (и оставить row reaper'у), **до того** как reaper его подберёт.

---

## 6. Часть 4: Single-flight gate

Живёт в [`infra/storage/integrity/lock.rs`](account-management/src/infra/storage/integrity/lock.rs). 236 строк. Используется integrity check + repair (НЕ bootstrap — у bootstrap своя координация через unique-index).

### 6.1 Зачем

Integrity check — дорогая операция (loads весь snapshot в память). Если две replic'и его одновременно запустят, обе будут грузить полный snapshot, обе будут эмитить per-category violation gauges → дашборды покажут двойной счёт. Single-flight cuts that.

### 6.2 Как устроена таблица

[m0003_create_integrity_check_runs.rs](account-management/src/infra/storage/migrations/m0003_create_integrity_check_runs.rs):
```sql
CREATE TABLE integrity_check_runs (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton
    worker_id UUID NOT NULL,
    started_at TIMESTAMPTZ NOT NULL
);
```

Только одна row может существовать (PK + CHECK). Контендер пытается INSERT — получает unique-violation → `IntegrityCheckInProgress`.

### 6.3 Three-transaction lifecycle

```
Tx1 (acquire):
  - sweep_stale (DELETE WHERE started_at < now() - MAX_LOCK_AGE)
  - INSERT (id=1, worker_id=current, started_at=now())
  - COMMIT

[long-running snapshot tx + classifiers]

Tx2 (release):
  - DELETE WHERE worker_id = current
  - Если rows_affected = 0 → emit warn "lock_evicted_by_sweep"
  - COMMIT
```

**Почему 3 транзакции, а не 1**: если acquire+work+release был бы одной TX, контендер не увидел бы row (uncommitted) и попытался бы acquire тоже → бесполезные round-trip'ы. С committed acquire row видна → контендер сразу получает `IntegrityCheckInProgress`.

### 6.4 Stale-lock cleanup

Если воркер крэшнулся посреди (упал hardware, OOM, etc) — row останется навечно. Защита: каждый `acquire_committed` сначала делает `sweep_stale` — DELETE'ит row со `started_at < now() - 1h`. То есть стрижку можно потерять максимум на час, потом следующий acquire её reset'нет.

### 6.5 Eviction warn-log (то, что мы тестируем)

Ситуация: наш воркер работает дольше `MAX_LOCK_AGE = 1h`. Контендерский `acquire_committed` приходит, sweep'ит нашу row, ставит свою. Когда мы наконец делаем `release_committed` — наш DELETE по `worker_id = self` находит **0 строк**.

Код это замечает ([lock.rs:151-156](account-management/src/infra/storage/integrity/lock.rs#L151-L156)):
```rust
if result.rows_affected == 0 {
    tracing::warn!(
        target: "am.integrity",
        worker_id = %worker_id,
        event = "lock_evicted_by_sweep",
        "integrity-lock release: zero rows affected; row was likely evicted by a stale-lock sweep"
    );
}
```

Это единственный operator-visible сигнал, что concurrent integrity-runs имели место. AM-стороннего теста на этот warn нет — архитектура `integrity_check_runs` будет заменена `modkit-coord` lease-моделью в отдельном follow-up PR, и весь age-based sweep уйдёт целиком.

---

## 7. Часть 5: Тесты

### 7.1 Структура

```
modules/system/account-management/account-management/
├── src/
│   ├── domain/
│   │   ├── bootstrap/service_tests.rs        ← bootstrap saga (lib tests, FakeRepo+FakeIdp)
│   │   ├── integrity_check/service_tests.rs  ← periodic loop tests
│   │   └── tenant/test_support/              ← FakeTenantRepo, FakeIdpProvisioner
│   └── infra/storage/integrity/
│       ├── classifiers/*_tests.rs            ← unit tests на каждый classifier (in-source)
│       └── repair_tests.rs                   ← unit tests на repair planner (in-source)
└── tests/                                     ← integration tests (separate test crate)
    ├── common/mod.rs                         ← shared helpers (setup_sqlite, seed_*, etc)
    ├── integrity_integration.rs              ← SQLite integration: 8 категорий + single-flight
    ├── integrity_integration_pg.rs           ← Postgres testcontainers (subset категорий)
    ├── lifecycle_integration.rs              ← lifecycle (create/delete/activate)
    └── repair_integration.rs                 ← repair end-to-end
```

### 7.2 3 E2E теста, добавленных в этой сессии

В [`bootstrap/service_tests.rs`](account-management/src/domain/bootstrap/service_tests.rs):

| Тест | Что пинит | Как |
|---|---|---|
| `run_returns_active_root_on_clean_noroot_path` | Green-path E2E: NoRoot → Insert → Finalize → Active | FakeOutcome::Ok + verify status=Active, closure self-row, provision_call_count == 1 |
| `run_with_provision_tenant_timeout_does_not_compensate` | **Critical**: timeout НЕ компенсирует | FakeOutcome::Hang (await pending::<()>()) + tokio::time::pause + advance(5s); assert row остаётся в Provisioning, deprovision_calls == 0 |
| `run_takes_over_when_peer_compensates_mid_resume_wait` | Takeover transition: Resume → NoRoot (peer compensated) → Insert → Active | seed_root_with_age(0) + spawn saga + repo.compensate_provisioning + advance(1500ms) |

**Почему это важно**: до этой сессии все Ok-возвращающие тесты `run()`'а проходили через **skip-paths** (ActiveRootExists, peer-finalised). Реальный finalize-and-activate путь ни одним тестом end-to-end не проверялся. Регрессия в `activate_tenant` или закрытии closure не сработала бы ни в одном существующем тесте.

### 7.3 Синхронизация тестов с tokio::time::pause

**Проблема**: saga имеет внутренние `.await` точки (sleep, timeout_at, IdP calls). Тест должен дождаться, когда saga парконется на конкретной точке, прежде чем advance'ать virtual time.

**Решение** (после ревью modkit + cypilot): использовать `tokio::sync::Notify` в FakeIdpProvisioner:
```rust
pub provision_entered: Arc<Notify>,

async fn provision_tenant(&self, req: &ProvisionRequest) -> Result<...> {
    self.provision_entered.notify_one();   // саге надо знать, что мы уже здесь
    let oc = self.outcome.lock().expect("lock").clone();
    match oc {
        FakeOutcome::Hang => {
            std::future::pending::<()>().await;  // никогда не вернётся
            unreachable!()
        }
        ...
    }
}
```

В тесте:
```rust
let saga = tokio::spawn(async move { svc.run().await });
provision_entered.notified().await;          // дождались парковки на pending future
tokio::time::advance(Duration::from_secs(5)).await;  // advance time → timeout_at срабатывает
```

Это **детерминистично**, в отличие от старого `for _ in 0..32 { yield_now }` подхода.

---

## 8. Часть 6: Что НЕ сделано и почему

| Пункт | Почему не сделано |
|---|---|
| Bound на `idp_wait_timeout_secs` в `BootstrapConfig::validate()` | Pre-existing, не в scope этой сессии. На overflow могут паниковать `Instant + Duration::from_secs(big_number)`. Тикет на следующий PR. |
| Memoization в `depth.rs` classifier | O(N²) на линейной цепочке N тенантов. Pre-existing, perf-finding. AM работает с reasonable hierarchy depths (< 100), так что не блокер. Тикет. |
| Wall-clock vs DB-time для `MAX_LOCK_AGE` cutoff | Pre-existing. Будет removed целиком когда AM мигрирует на `modkit-coord`. |
| Subtree audit/repair scope | Интенционально удалён из реализации: фича не нужна, а добавлять документацию под несуществующую функциональность смысла нет. |
| `idp_unavailable` structural discriminator на public Problem envelope | Намеренно не выводится: внутренности AM ("кухня") не должны expose'иться через canonical-error envelope. Observability через метрики, не через структуру ошибок. |
| `actor=system` audit envelope для AM-owned non-request transitions (5 `TODO(events)` маркеров) | Открыто, заблокировано на платформенный append-only audit-sink (event-bus), которого пока не существует. Сейчас стоит структурный лог на `tracing` target `am.events` как v1-stand-in. |
| Migration AM `integrity_check_runs` на `modkit-coord` | Это отдельный follow-up PR в cascade'e после `modkit-coord` implementation PR. Сейчас (PR #8) AM использует свой singleton-gate. |

---

## 9. Куда смотреть дальше

Если ты только что прочёл этот документ и тебе надо реально работать с кодом:

1. **Чтобы понять integrity check**: начни с [`tenant/integrity.rs`](account-management/src/domain/tenant/integrity.rs) (типы) → [`infra/storage/integrity/loader.rs`](account-management/src/infra/storage/integrity/loader.rs) (snapshot loading) → один из classifier'ов в [`classifiers/`](account-management/src/infra/storage/integrity/classifiers/) → потом [`repo_impl/integrity.rs`](account-management/src/infra/storage/repo_impl/integrity.rs) (orchestration).

2. **Чтобы понять repair**: [`infra/storage/integrity/repair.rs`](account-management/src/infra/storage/integrity/repair.rs) — основная логика. Тесты в [`repair_tests.rs`](account-management/src/infra/storage/integrity/repair_tests.rs).

3. **Чтобы понять bootstrap saga**: [`bootstrap/service.rs`](account-management/src/domain/bootstrap/service.rs). Начни с `pub async fn run()` (~50 LOC) → `BootstrapState` enum → 7 step-функций. Тесты в [`service_tests.rs`](account-management/src/domain/bootstrap/service_tests.rs).

4. **Чтобы понять periodic loop**: [`integrity_check/service.rs`](account-management/src/domain/integrity_check/service.rs). Тикает каждые `check_interval_secs`, делает acquire/check/(maybe repair)/release.

5. **Чтобы понять test fakes**: [`tenant/test_support/`](account-management/src/domain/tenant/test_support/). `FakeTenantRepo` мирорит production semantics включая `ux_tenants_single_root` ограничение и reaper-fence; `FakeIdpProvisioner` — 5 outcome'ов (Ok/CleanFailure/Ambiguous/Unsupported/Hang) для разных ветвей saga.

---

**Если что-то непонятно в этом документе — это бага. Открой issue / спроси старшего.**
