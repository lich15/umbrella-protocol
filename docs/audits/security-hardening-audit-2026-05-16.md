# Аудит безопасности и усиление, 2026-05-16

Этот документ фиксирует свежую recon-breadth итерацию активной красной команды:
я прошёл по 21 крейту Umbrella Protocol с моделью угроз адверсария уровня D из
SPEC-01 §4 (полный сетевой MITM, частичная компрометация инфры, HSM-стенды,
длительный пассивный сбор), искал пробелы вне существующего реестра боевых
атак и закрывал каждую подтверждённую находку failing-then-passing атакующим
тестом, минимальным исправлением, строкой в реестре и записью в этом отчёте.

Это не заявление "невозможно взломать". Это запись о том, что закрыто
локально кодом, тестами и скриптами в рамках одного раунда A-level rigor per
finding с PhD-style adversary mindset. Реальные серверы, настоящие
Android/iOS-устройства, внешний формальный прогон, длинный ночной fuzz и
независимый аудит остаются обязательными выпускными границами.

Базовое описание раунда:
`docs/superpowers/specs/2026-05-16-phd-recon-breadth-audit-design.md`
(commit `4c67f172`). План:
`docs/superpowers/plans/2026-05-16-phd-recon-breadth-audit.md`
(commit `cdbb6c4a`).

## Что было найдено и исправлено

| Область | Дыра простыми словами | Что сделано |
|---|---|---|
| _placeholder — заполнится по ходу_ | | |

## Critical findings

_Раздел заполняется при появлении Critical-серьёзности по §7а спецификации.
Если в раунде Critical-находок нет, секция остаётся пустой с явной пометкой._

## Новые реальные проверки

_Список новых attack-тестов с краткими описаниями._

## Что прошло локально

_Список cargo/script команд с результатами._

## Что не закрыто этой итерацией

- настоящие Android/iOS-устройства и их platform attestation;
- настоящее серверное развёртывание уровня "миллион активных пользователей";
- живой KT gossip между независимыми свидетелями и клиентами;
- длинный ночной fuzz перед выпуском в чистом окружении;
- свежий внешний формальный прогон и независимый ручной аудит.

Правило остаётся прежним: если путь не связан до конца, он должен закрыто
отказывать или быть явно назван тестовым стендом.

## Tier 1 progress

- `umbrella-identity` (2026-05-16): пройдены 20 классов §3 spec. Подтверждённых
  закрытых-тестом находок: 0. Рассмотренные кандидаты:
  - **Stack-residual HMAC intermediates в `MasterKey::from_seed` и
    `derive_child`** (классы 16 — zeroize, и 9 — частично).
    `let i = mac.finalize().into_bytes()` и копия `full = [0u8; 64]` в
    `derive_child` содержат частичный ключевой материал
    (`ExtendedSecret`/`ChainCode`) на стеке и не зануляются. Сами owning-типы
    (`MasterKey`, `ExtendedSecret`, `ChainCode`) — `ZeroizeOnDrop` ✓, но
    промежуточные стековые буферы — нет. Severity: **Low** по §7а
    (hygiene defense-in-depth без поведенческого импакта; реализуемый
    эксплойт требует уже скомпрометированной памяти процесса, что выходит
    за пределы D-level threat model данного раунда). Решение этого раунда:
    зафиксировать наблюдение, не закрывать сейчас, кандидат для
    follow-up уборочного PR (Pattern: явная `Zeroize` на промежуточный
    `[u8; 64]` копию HMAC-SHA512 output до выхода из функции).
  - Прочее: все sensitive типы имеют `ZeroizeOnDrop` и ручной `Debug` с
    redaction; `IdentityError` варианты не утекают байты ключей; HKDF
    labels (`umbrellax-device-attestation-v1`, `umbrellax-identity-rotation-v1`,
    `umbrellax-cloud-wrap-recovery-xwing-v1`, `umbrellax-slh-dsa-backup-v1`,
    `umbrellax-slh-dsa-backup-rotation-v1`, `umbrellax-hybrid-identity-mldsa-v1`,
    `umbrellax-hybrid-device-mldsa-v1`) попарно различны и
    version-суффиксированы; источники RNG — `OsRng` или
    `ChaCha20Rng::from_seed(HKDF(secret))` (детерминистичный derive для PQ);
    `derive_rotated_identity_material` сравнивает старый identity_pubkey
    через `ct_eq`; `PartialEq` присутствует только на публичных типах;
    `from_bytes` для всех wire-форматов проверяет точную длину; BIP-39
    парсинг проверяет word count и checksum до allocation.
  - Категории 1/7/13: применимы частично — identity не пересекает FFI
    напрямую, не имеет V1/V2 wire-формата (single attestation version),
    cross-crate state в основном через `KeyStore` trait с `Mutex`-защитой.
  - Категории 18/19/20: n/a (нет рекурсивных парсеров, нет
    allocator-зависимых hot paths, нет floating-point).

## Tier 2 progress

_Заполняется по ходу обхода Tier 2 крейтов._

## Tier 3 progress

_Заполняется по ходу обхода Tier 3 крейтов._

## Tier 4 sanity

_Заполняется по ходу обхода Tier 4 крейтов._

## English mirror

This document records the 2026-05-16 recon-breadth active red-team round: a
walk over the 21 Umbrella Protocol crates under the SPEC-01 §4 D-level threat
model (full network MITM, limited infra compromise, HSM-backed forgery rigs,
long-term passive collection), looking for blind spots beyond the existing
`docs/security/protocol-core-attack-gates.md` matrix and the
`external-crypto-attack-ledger-*` files, closing every confirmed finding with
a failing-then-passing attack test, a root-cause fix, a ledger row, and an
entry in this report.

This is not a claim of unbreakability. It records what is closed locally by
code, tests, and scripts during one A-level-per-finding round with a
PhD-style adversary mindset. Real server deployment, real Android/iOS
devices, external formal runs before release, long overnight fuzzing, and
independent manual review remain mandatory release boundaries.

Round spec:
`docs/superpowers/specs/2026-05-16-phd-recon-breadth-audit-design.md`
(commit `4c67f172`). Plan:
`docs/superpowers/plans/2026-05-16-phd-recon-breadth-audit.md`
(commit `cdbb6c4a`).

### What was found and fixed

_To be filled per finding._

### Critical findings

_Filled if any Critical-severity finding per §7a appears. Otherwise marked
explicitly empty._

### New real checks

_List of new attack tests with short descriptions._

### What passed locally

_List of cargo / script commands with results._

### What is not closed by this round

- real Android/iOS devices and their platform attestation;
- real server deployment under realistic load;
- live KT gossip across independent witnesses and clients;
- long overnight fuzzing on a clean environment before release;
- a fresh external formal run and an independent manual audit.

The release rule remains: if a path is not fully wired, it must fail closed
or be documented as a test harness.
