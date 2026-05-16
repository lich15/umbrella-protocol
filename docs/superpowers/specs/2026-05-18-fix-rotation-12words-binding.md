# Implementation Spec — Вариант А: 12-Words Binding для Identity Rotation (F-PHD-RETRO-3-E fix)

> **Для нового сеанса:** этот документ — самостоятельное задание на
> реализацию **Варианта А** починки F-PHD-RETRO-3-E (захват аккаунта
> через утечку 24 слов). В нём весь нужный контекст. Прочитай целиком
> до начала работы.

## English

### 1. Problem statement

Per audit `docs/audits/security-hardening-audit-2026-05-17.md`
finding F-PHD-RETRO-3-E: identity rotation acceptance currently requires
only two Ed25519 signatures (old_identity_sk + new_identity_sk) над
`canonical_signing_input_rotation`. NO platform attestation, NO
active-device co-signature, NO 12-words code recovery commitment.

Adversary with leaked 24 words can:
1. Recover old_identity_sk locally.
2. Generate fresh new_identity_sk locally.
3. Sign rotation record with both keys.
4. Submit to KT — accepted.
5. All victim's devices cascade-revoked.
6. Adversary controls identity → bootstraps device → unwraps all messages.

Demonstration: `crates/umbrella-backup/tests/attack_rotation_24words.rs`
currently passes (showing attack works).

### 2. Solution overview — Variant A

Bind a **commitment to the 12-words code recovery entropy** into
`canonical_signing_input_rotation`. The commitment is a one-way function
of the 12-words entropy plus a server-side nonce; cannot be reversed to
the entropy. Server compares the commitment in the rotation record
against the **public half** stored in the KT log at account bootstrap.

After the fix, rotation acceptance requires:
- old_identity_sk signature (24-words knowledge) ✓
- new_identity_sk signature (any fresh key) ✓
- **commitment matching the public half stored in KT** (12-words knowledge) — NEW

Adversary with 24 words alone cannot compute the commitment without
12 words → server rejects rotation.

### 3. Cryptographic construction

Let `e12 = CodeRecoveryMnemonic::entropy` be the 16-byte entropy of the
12 words.

**Public half (stored in KT at bootstrap):**

```
public_half = HKDF-SHA256(
    salt = "umbrellax-12words-public-half-v1",
    ikm  = e12,
    info = identity_pubkey || account_index_be,
    L    = 32 bytes
)
```

This is published in the KT log entry for the account at the time of
first registration (or first 12-words generation). It is a one-way image
of e12 — cannot be reversed. Different accounts get different public
halves (info-binding to identity_pubkey).

**Rotation commitment (in rotation record):**

```
rotation_commitment = HKDF-SHA256(
    salt = "umbrellax-12words-rotation-bind-v1",
    ikm  = e12,
    info = rotation_canonical_v1 || old_identity_pubkey || new_identity_pubkey,
    L    = 32 bytes
)
```

This is computed at rotation time. Binds the 12-words entropy to the
specific (old, new) identity_pubkey pair — prevents replaying a
commitment across different rotations.

**Server-side verification:**

To verify that the commitment is "correct" without knowing e12, the
server cannot directly compute either value. Instead, the **client**
provides a zero-knowledge-style proof. Two options:

- **Option A.1 (simplest):** include both `public_half` and
  `rotation_commitment` in the rotation record. Server checks
  `public_half == stored_public_half_in_kt`. This is **NOT zero-knowledge**
  — public_half is public anyway (it's in KT). The check is just
  "do you know e12 such that HKDF(e12, info_a) == public_half AND
   HKDF(e12, info_b) == rotation_commitment with the right info bytes?"
  Since adversary doesn't know e12, he cannot construct
  rotation_commitment that "is consistent" with public_half for new info
  bytes. Actually — if adversary knows public_half, can he forge
  rotation_commitment? No — HKDF is one-way, knowing public_half doesn't
  let you compute another HKDF output of the same e12. So this is sound.

- **Option A.2 (more rigorous):** use a Schnorr-style proof of knowledge
  of e12. Server verifies the proof against public_half. This is more
  complex but fully zero-knowledge. **NOT recommended for v1.2.0** —
  add complexity later if needed. Variant A.1 is sufficient for the
  stated threat model.

**Selected: Option A.1.**

### 4. Files to modify

#### 4.1 `crates/umbrella-identity/src/code_recovery.rs`

Add:

- New constant `CODE_RECOVERY_PUBLIC_HALF_HKDF_INFO = b"umbrellax-12words-public-half-v1"`.
- New constant `CODE_RECOVERY_ROTATION_BIND_HKDF_INFO = b"umbrellax-12words-rotation-bind-v1"`.
- New function `CodeRecoveryMnemonic::public_half(&self, identity_pubkey: &[u8; 32], account: u32) -> [u8; 32]`.
- New function `CodeRecoveryMnemonic::rotation_commitment(&self, canonical_v1: &[u8], old_pk: &[u8; 32], new_pk: &[u8; 32]) -> [u8; 32]`.

Both use `Hkdf::<Sha256>` from `umbrella-crypto-primitives` (already a
dependency).

Add `pub` re-exports in `umbrella-identity/src/lib.rs`.

#### 4.2 `crates/umbrella-backup/src/cloud_wrap/identity_rotation.rs`

Modify wire format:

- Bump `AUTHORIZATION_WIRE_VERSION` from `0x01` to `0x02` ONLY for
  `IdentityRotationRecord` (keep v1 for `DeviceAuthorizationRequest`,
  `Approval`, `Revocation` to avoid wider migration).
- Better: introduce a **per-record version field** `pub rotation_wire_version: u8`
  with two valid values: `0x01` (legacy) and `0x02` (with commitment).
- Add new field `pub rotation_commitment: [u8; 32]` to `IdentityRotationRecord`,
  populated for v2 only (v1 has zeros).
- Update `IDENTITY_ROTATION_LEN` for v2: add 32 bytes for commitment.
  v1 length unchanged.
- Update `canonical_signing_input_rotation`:
  - For v1: unchanged.
  - For v2: append `commitment` to the signed bytes.
- Update `seal_identity_rotation_record`: take optional `commitment`
  parameter. If `Some(c)`, build v2; if `None`, build v1 (deprecated but
  accepted for migration window).
- Update `IdentityRotationRecord::verify`:
  - v1: behavior unchanged.
  - v2: additionally verify that `commitment` field is non-zero (sanity)
    AND that both signatures cover the canonical bytes WITH commitment.
- Update `IdentityRotationRecord::from_bytes` / `encode` to handle both
  v1 (137 + 64*2 = 265 bytes? — re-check current value) and v2
  (legacy length + 32 bytes for commitment).
- Add `pub fn rotation_commitment(&self) -> Option<&[u8; 32]>` accessor
  returning `None` for v1.

#### 4.3 `crates/umbrella-kt/src/authorization_entries.rs`

- Modify `KtLogState` to store the `code_recovery_public_half: Option<[u8; 32]>`
  for each identity (published at bootstrap; immutable for life of
  identity — rotates with new identity).
- Modify `apply_identity_rotation`:
  - Read `rotation.rotation_commitment` if v2.
  - Read `log_state.code_recovery_public_half` for current identity.
  - **Verify**: if `rotation.wire_version == v2`, check that the
    commitment is non-zero AND that the **client also provides a
    proof of knowledge** of `e12` such that HKDF(e12, public_half_info) == public_half.
  - Actually — simpler: server stores `public_half` for current identity.
    Client constructs `rotation_commitment` from `e12` and broadcasts
    in the rotation record. Server **cannot directly verify**
    `commitment == HKDF(e12, ...)` without knowing `e12`. But here's
    the trick: server **can** verify that **the same e12** produced
    both the stored `public_half` (at bootstrap) AND the new
    `rotation_commitment` (at rotation), by checking a **linking proof**.
  - **Simplest version**: client publishes BOTH `public_half` (re-published
    each rotation) AND `rotation_commitment`. Server checks
    `published_public_half == stored_public_half`. If match, server
    trusts that client knew e12 to compute it. Adversary without e12
    cannot produce a `public_half` that matches the stored one (HKDF
    is preimage-resistant). And the `rotation_commitment` part isn't
    actually verified directly — its purpose is to be **bound into the
    canonical signing input** so that the signatures cover it. The
    actual gate is `published_public_half == stored_public_half`.

  Re-spec: rotation record carries `public_half_proof: [u8; 32]` (the
  client's recomputation of public_half from e12, identity_pubkey,
  account). Server compares against `stored_public_half`. Adversary
  without e12 cannot recompute. Done.

#### 4.4 `crates/umbrella-backup/tests/attack_rotation_24words.rs`

After fix lands:

- Test `attack_rotation_via_leaked_24_words_alone_currently_passes_verify`
  must now FAIL (because v2 rotation requires commitment, and adversary
  with 24 words alone cannot produce valid commitment).
- Rename the test to reflect new role:
  `regression_attack_rotation_via_leaked_24_words_alone_now_blocked`.
- Add new positive-path test:
  `legitimate_rotation_with_both_24_and_12_words_passes`.
- Add new negative-path test:
  `attack_rotation_with_24_words_and_wrong_12_words_blocked`.

#### 4.5 Tamarin model — `crates/umbrella-formal-verification/models/multi_device_authorization.spthy`

- Uncomment the `adversary_publish_rotation` rule (currently in comment block).
- Add `Eq(public_half_proof, expected_public_half_from_e12)` premise to
  `rotate_identity_atomic` and `adversary_publish_rotation`.
- Add new lemma `rotation_requires_both_24_and_12_words`:
  for any IdentityRotated event, there must exist a CodeRecoveryKnowledge
  event for the same identity (modelling e12 knowledge).
- Re-prove all lemmas. The attack lemma
  `twentyfour_words_leak_alone_insufficient_REGRESSION` (currently
  commented) should now verify (not falsify).

### 5. Wire format migration story

`IdentityRotationRecord` has two versions co-existing during transition:

- **v1 (legacy):** existing wire format. Acceptance by KT publisher
  **deprecated after migration deadline**.
- **v2 (with commitment):** new wire format. Required after migration.

**Migration phases:**

**Phase 1 (release 1.2.0):** Both v1 and v2 accepted. New rotations
generated client-side use v2 always. v1 acceptance logged with warning.

**Phase 2 (release 1.3.0, ≥3 months after 1.2.0):** v1 no longer
accepted by KT publisher. Server rejects with `RotationWireVersionRetired`.
Existing v1-rotated identities continue to function with their new
identity_pubkey — no need to "re-rotate".

**Phase 3 (release 1.4.0):** Remove v1 code paths entirely. Wire-format
unification.

### 6. UX changes

#### 6.1 At account creation (new users)

Onboarding flow changes:

- Step 1: generate identity, show 24 words mnemonic.
- Step 2: instruct user to write down on **separate piece of paper** (paper A).
- Step 3: generate code-recovery 12 words, show.
- Step 4: instruct user to write down on **another separate piece of paper** (paper B).
- Step 5: warn: "**Never store these two pieces of paper together.** If
  someone obtains both, they can take over your account. If they have
  only one, your account remains safe."
- Step 6: ask user to confirm by re-entering both phrases.
- Step 7: publish `public_half` in KT.

#### 6.2 At account recovery (existing users post-migration)

Recovery flow changes:

- Step 1: ask for 24 words → derive identity_sk.
- Step 2: ask for 12 words → derive e12.
- Step 3: derive new identity (catastrophic recovery formula).
- Step 4: compute new `public_half` and `rotation_commitment`.
- Step 5: submit v2 rotation record.

**Important:** existing users (pre-1.2.0) **without 12 words** cannot
do v2 rotation. Migration path:
- If user still has 24 words AND access to active device → log in,
  generate 12 words (server allows one-time bootstrap), store
  `public_half` retroactively. Now they have both factors.
- If user has only 24 words and no active device → **stuck**. Tell
  them upfront in the 1.2.0 release notes: "if you only have 24 words
  and lost all devices, recover within 1.2.0 grace period; after
  Phase 2 deadline, recovery requires 12 words."

#### 6.3 At rotation (existing users with both factors)

Rotation flow:
- App asks for 12 words (or reads from secure storage if user opted in
  to that — discouraged for security).
- App computes commitment.
- App submits v2 rotation record.

### 7. Test plan

#### 7.1 Unit tests in `code_recovery.rs`

- `public_half_is_deterministic_from_entropy_identity_account`
- `public_half_differs_for_different_identities`
- `rotation_commitment_is_deterministic_from_entropy_canonical_pks`
- `rotation_commitment_differs_for_different_canonical_inputs`

#### 7.2 Unit tests in `identity_rotation.rs`

- `seal_v1_legacy_path_works`
- `seal_v2_with_commitment_works`
- `verify_v2_succeeds_with_correct_commitment`
- `verify_v2_fails_with_zero_commitment`
- `from_bytes_round_trips_v1_and_v2`

#### 7.3 Integration tests in `authorization_entries.rs`

- `apply_v2_rotation_with_correct_public_half_proof_succeeds`
- `apply_v2_rotation_with_wrong_public_half_proof_fails`
- `apply_v1_rotation_during_migration_warns_but_succeeds`

#### 7.4 Attack regression tests in `attack_rotation_24words.rs`

- `regression_attack_rotation_via_leaked_24_words_alone_now_blocked` (new)
- `legitimate_rotation_with_both_24_and_12_words_passes` (new)
- `attack_rotation_with_24_words_and_wrong_12_words_blocked` (new)

#### 7.5 Tamarin model verification

```
tamarin-prover --prove crates/umbrella-formal-verification/models/multi_device_authorization.spthy
```

Expected:
- All existing lemmas: verified.
- `adversary_publish_rotation` rule (uncommented): valid.
- `twentyfour_words_leak_alone_insufficient_REGRESSION` (uncommented): verified.
- New `rotation_requires_both_24_and_12_words`: verified.

### 8. Six-question PhD-B self-check applied to this fix

Before the fix lands as v1.2.0:

1. **Findings count 5+**: only this one fix closes F-PHD-RETRO-3-E.
   Acceptable since this is a **single-finding remediation block**,
   not a multi-finding audit round.
2. **Test naming**: `attack_*` and `regression_*` adversarial naming
   per §7.4.
3. **Tamarin engagement**: re-prove all lemmas + uncomment regression
   lemma. ✓
4. **dudect**: `CodeRecoveryMnemonic::public_half` and
   `rotation_commitment` must be constant-time over `e12`. Add to
   `dudect_constant_time.rs` with 1M+ sample budget.
5. **Reduction sketch**: prove that adversary without `e12` cannot
   produce valid `public_half` matching the stored one. Standard
   HKDF preimage resistance argument: `Adv^Preimage_A ≤ 2^-256` for
   SHA-256 baseline.
6. **Literature**: HKDF (RFC 5869 Krawczyk), Schnorr 1991 (proof of
   knowledge background), Bellare-Rogaway 1993 (random oracle model
   for HKDF analysis), prior PhD findings F-PHD-RETRO-3-A through E.

### 9. Estimated work

- Code changes: ~600 LoC + 300 LoC tests.
- Tamarin model: ~50 LoC additions + re-prove (≤ 10s expected).
- dudect extension: ~80 LoC.
- Doc updates: ~200 LoC across release notes, audit ledger, attack
  ledger.
- Total: ≈ 4-6 hours of focused implementation.

### 10. Open questions for owner before implementation

1. **Wire-format version field placement.** Bump
   `AUTHORIZATION_WIRE_VERSION` (affects all four record types) OR
   introduce per-record `rotation_wire_version` (more local but uglier)?
   Recommendation: per-record.

2. **public_half publication timing.** Publish at account creation
   only, OR re-publish at every rotation?
   - Publish-once: cleaner; depends on KT log having an "identity
     metadata" entry separate from device entries.
   - Re-publish-every-rotation: simpler integration, costs ~32 bytes
     per rotation.
   - Recommendation: publish-once at creation; tie to identity_pubkey
     in KT.

3. **Migration deadline.** How long is Phase 1 (both v1 and v2
   accepted)? 3 months? 6 months? Affects how many users have time to
   acquire 12-words bootstrap (if they don't already).

4. **What about existing users without 12 words?** Pre-1.2.0 users may
   not have ever generated 12 words. Force them to generate at next
   app open? Soft-deprecate v1 with warning UI?

5. **Storage of e12 on device.** Discouraged for security (it's a
   secret like 24 words). Each rotation, user re-enters 12 words.
   Confirm UX is acceptable.

---

## Русский

### 1. Постановка проблемы

Из аудита `docs/audits/security-hardening-audit-2026-05-17.md` находка
F-PHD-RETRO-3-E: запись смены главного ключа принимается на основе
только двух подписей. Без платформенного удостоверения, без подтверждения
от активного устройства, без привязки к 12 словам кода восстановления.

Злоумышленник с утечкой 24 слов может локально:
1. Восстановить старый ключ.
2. Сгенерировать свежий новый ключ.
3. Подписать запись смены обоими.
4. Опубликовать на сервер прозрачности — принимается.
5. Все устройства жертвы каскадно отзываются.
6. Злоумышленник контролирует учётную запись → бутстрапит своё
   устройство → расшифровывает всю переписку.

Демонстрация: `crates/umbrella-backup/tests/attack_rotation_24words.rs`
сейчас проходит (показывая что атака работает).

### 2. Обзор решения — Вариант А

Привязать **отпечаток 12 слов** к канонической строке подписи
смены ключа. Отпечаток — это односторонняя функция от 12-словного
семени и serverского контекста; восстановить семя из отпечатка
математически невозможно. Сервер сравнивает отпечаток в записи смены
с **публичной половинкой**, сохранённой в журнале прозрачности при
регистрации учётной записи.

После починки приём смены требует:
- подпись старым ключом (знание 24 слов) ✓
- подпись новым ключом (любой свежий ключ) ✓
- **отпечаток, сходящийся с публичной половинкой в журнале** (знание
  12 слов) — НОВОЕ

Злоумышленник с одними 24 словами не может посчитать правильный
отпечаток без 12 слов → сервер отказывает в смене.

### 3. Криптографическая конструкция

Пусть `e12 = CodeRecoveryMnemonic::entropy` — 16-байтовая энтропия
12 слов.

**Публичная половинка (сохраняется в KT при создании учётной записи):**

```
public_half = HKDF-SHA256(
    salt = "umbrellax-12words-public-half-v1",
    ikm  = e12,
    info = identity_pubkey || account_index_be,
    L    = 32 байта
)
```

Публикуется в журнале при первичной регистрации (или при первой
генерации 12 слов). Одностороннее преобразование e12 — невозможно
восстановить e12 из public_half. Разные учётные записи получают разные
public_half (благодаря info-привязке к identity_pubkey).

**Отпечаток смены (в записи смены ключа):**

```
rotation_commitment = HKDF-SHA256(
    salt = "umbrellax-12words-rotation-bind-v1",
    ikm  = e12,
    info = rotation_canonical_v1 || old_identity_pubkey || new_identity_pubkey,
    L    = 32 байта
)
```

Вычисляется в момент смены. Связывает 12-словную энтропию с конкретной
парой (old, new) identity_pubkey — предотвращает повторное использование
отпечатка между разными сменами.

**Серверная проверка:**

Сервер не знает e12, поэтому не может посчитать значения напрямую.
Клиент публикует и `public_half`, и `rotation_commitment` в записи
смены. Сервер сравнивает опубликованную `public_half` с той что
сохранена в KT при регистрации. Если совпадает — клиент знает e12,
потому что HKDF необратима. Злоумышленник без e12 не может произвести
public_half, сходящееся с сохранённой.

### 4-10

См. английскую секцию выше — структура файлов, миграция, UX, тесты,
самопроверка, оценка работы, открытые вопросы — идентичны.

### 11. Открытые вопросы перед реализацией (для владельца)

1. **Размещение поля версии формата.** Поднять
   `AUTHORIZATION_WIRE_VERSION` (затронет все четыре типа записей)
   ИЛИ ввести поле версии прямо в `IdentityRotationRecord`?
   Рекомендую: на уровне отдельной записи.

2. **Когда публикуется public_half.** При создании учётной записи
   только, либо при каждой смене?
   - Только при создании: чище; зависит от наличия в KT отдельной
     записи «метаданные учётной записи».
   - При каждой смене: проще интеграция, +32 байта на смену.
   - Рекомендую: публиковать один раз при создании, привязывать к
     identity_pubkey в KT.

3. **Срок миграции.** Сколько длится Фаза 1 (оба формата принимаются)?
   3 месяца? 6 месяцев? Влияет на то сколько у пользователей будет
   времени получить 12 слов если их у них ещё нет.

4. **Существующие пользователи без 12 слов.** Пользователи до 1.2.0
   могли никогда не генерировать 12 слов. Заставить сгенерировать при
   следующем входе в приложение? Мягко отказывать v1 с предупреждением?

5. **Хранение e12 на устройстве.** По безопасности — не рекомендуется
   (это секрет уровня 24 слов). При каждой смене пользователь вводит
   12 слов заново. Подтвердить что UX допустим.
