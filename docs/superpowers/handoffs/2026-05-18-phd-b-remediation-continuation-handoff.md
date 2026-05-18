# PhD-B Remediation Continuation Handoff (для следующего чата)

**Дата:** 2026-05-18
**Состояние:** 5 находок закрыто в текущей сессии; 12 открытых до полной готовности.
**Цель следующего чата:** закрыть оставшиеся 12 находок из 5-проходного PhD-B аудита.

---

## Промт для копирования в новый чат

Скопируй всё что ниже (от строки `Контекст проекта` до конца документа) в новый чат — это полная самодостаточная briefing для продолжения работы.

---

## Контекст проекта

Я провожу ремедиацию (закрытие) дыр найденных в 5-проходном аудите безопасности уровня кандидата наук криптомессенджера **Umbrella Protocol** — приложения для миллиарда пользователей с защитой от противника уровня D из документа SPEC-01 раздел 4 (государственная разведка / организованная преступность с физическим доступом к устройству, 13 угроз).

5 проходов аудита (Pass 1 → Pass 5) завершены 2026-05-18. В текущей сессии ремедиации закрыто 5 находок из 17 открытых. Осталось 12 находок до полной готовности к выпуску v1.0.0.

## Где мы сейчас

- **Репозиторий:** `/Users/daniel/Documents/Projects/Messenger/Umbrella Protocol`
- **Ветка:** `main` (главная)
- **HEAD на момент handoff:** `b48191b7` (F-MLS-1 closure compile-time gate)
- **Рабочая копия:** чистая, нет несохранённых изменений
- **Локальные коммиты:** 11, **не отправлены на сервер** (НЕ делать `git push` без явной просьбы пользователя)

### История коммитов 5-проходного аудита + ремедиации (от старых к новым)

```
acff5e5b Security hardening: PhD-level audits, distributed identity, PSI discovery
999b6893 docs(audit): PhD-B full sweep Pass 1 — 3 CRITICAL + 1 HIGH findings
89357246 docs(audit): PhD-B full sweep Pass 2 — 1 HIGH + 7 MINOR findings
82dd8377 docs(audit): PhD-B Pass 2 supplemental — closes 4 DEFER items
21239c89 docs(audit): PhD-B full sweep Pass 3 — 3 HIGH + 1 MEDIUM new + 5 MEDIUM formal-model tautology cluster
f54069c0 docs(audit): PhD-B full sweep Pass 4 — 1 CRITICAL NEW + 2 HIGH/HONEST GAP NEW + 1 MEDIUM NEW
4ddcc4bc docs(audit): PhD-B Pass 4 supplemental — 6 PASS+ exemplars
0f72bad1 tests(audit): PhD-B Pass 4 real-vs-paperwork closure — 3 CRITICAL exploit demonstrators
dff106fe docs(audit): PhD-B full sweep Pass 5 — final consolidation + dudect 1M cross-cutting + ship/no-ship decisions
471e7928 fix(ffi): F-FFI-2 CRITICAL closure — session-handle pattern eliminates session-key hex leak across FFI
456ffe7f fix(client): F-1 CRITICAL closure — Shamir 3-of-5 Lagrange interpolation replaces XOR-combine placeholder
f68c6fa6 fix(tests): F-3 CRITICAL closure — rename misleading R23 attack test to honest decision-logic-model
2784e058 fix(identity): F-IDENT-37 MEDIUM closure — RotatedIdentityMaterial.seed → Box<[u8; 64]> heap-resident
b48191b7 fix(mls): F-MLS-1 HIGH closure — compile-time gate on UmbrellaXWingProvider zeroed-witness fallback
```

## Что уже закрыто в предыдущих сессиях (5 closures)

| Находка | Степень | Коммит | Файл и метод фикса |
|---------|---------|--------|---------------------|
| **F-FFI-2** | КРИТИЧНАЯ | `471e7928` | `crates/umbrella-ffi/src/export/onboarding.rs` — session-handle pattern; UnlockResultFfi содержит `identity_pk_hex` + opaque `session_handle` (32-char hex); сеансовые ключи остаются в `OnboardingHandle.sessions: Mutex<HashMap<String, UnlockSession>>` в защищённой памяти; тест-rig метод `unlock_with_pin_for_test_rig` под `#[cfg(any(test, feature = "test-utils"))]` для R20 lldb измерений; 4 новых regression теста в `crates/umbrella-ffi/tests/f_ffi2_production_session_handle.rs` |
| **F-1** | КРИТИЧНАЯ | `456ffe7f` | `crates/umbrella-client/src/keystore/distributed_identity_client.rs` — XOR-combine заменён на Shamir 3-of-5 интерполяцию Лагранжа над полем кривой 25519; новая функция `lagrange_combine_shares(shares: &[(u8, [u8; 32])]) -> [u8; 32]`; positive regression тест `lagrange_reconstruction_yields_same_master_for_different_quora`; `curve25519-dalek` добавлен в direct deps |
| **F-3** | КРИТИЧНАЯ | `f68c6fa6` | `crates/umbrella-client/tests/` — переименование `attack_r23_5_registry_detects_fake_version.rs` → `decision_logic_r23_5_registry_acceptance_gate.rs` + 4 теста с честным `decision_logic_*` prefix + prominent disclaimer что это decision-logic model не real attack regression; real Sigstore/CT/cosign integration deferred to v1.1.x |
| **F-IDENT-37** | СРЕДНЯЯ | `2784e058` | `crates/umbrella-identity/src/code_recovery.rs` — `RotatedIdentityMaterial.seed: [u8; 64]` → `Box<[u8; SEED_LEN]>` heap-resident + custom Zeroize/ZeroizeOnDrop/Drop + pointer-arithmetic regression test `f_ident_37_closure_rotated_identity_material_seed_is_heap_resident` (analog R7-3 closure) |
| **F-MLS-1** | СЕРЬЁЗНАЯ | `b48191b7` | `crates/umbrella-mls/src/provider/xwing.rs` — удалены `Default` impl + `pub fn new()` полностью; добавлен `new_for_kat_tests_only()` под `#[cfg(any(test, feature = "test-utils"))]`; production builds физически не могут construct provider без explicit witness через `with_hedged_witness(witness)`; `test-utils` feature добавлен в Cargo.toml; 20+ test callsites обновлены |

Все тесты проходят: `cargo check --workspace --offline` PASS, все unit + integration тесты PASS для затронутых крейтов.

## Что осталось — 12 открытых находок

См. полный отчёт: `docs/audits/phd-b-final-consolidation-2026-05-18.md`

### Track A — Последняя критичная (блокирует v1.0.0 выпуск, ~6-8 часов + согласование с командой сервера)

#### F-2 CRITICAL — анонимные номера локально выводятся из ПИН + соли

**Файл:** `crates/umbrella-client/src/keystore/distributed_identity_client.rs:250-263`

**Текущее состояние** (плохое):
```rust
let pin_root = pin_kdf::derive_pin_root(&input.pin, &account_local_salt)?;
let mut anon_seed = [0u8; 32];
Hkdf::<Sha256>::new(Some(&account_local_salt), pin_root.expose())
    .expand(b"umbrella-r6/anon-seed/v1", &mut anon_seed)?;
let per_server_anonymous_ids = anonymous_id::derive_all_anonymous_ids(&anon_seed)?;
```

5 анонимных серверных номеров (5 × 32 = 160 байт) полностью **выводятся локально на устройстве** из (ПИН, account_local_salt). Это противоречит дизайну раунда 7 (PSI = Private Set Intersection) — анонимные номера должны выдаваться **на стороне серверов** через OPRF (Oblivious Pseudo-Random Function — алгоритм слепого псевдослучайного вычисления RFC 9497).

**Эксплойт:** Демонстратор `attack_phd4_f2_anon_ids_independently_derivable_from_pin_plus_salt` в `crates/umbrella-tests/tests/attack_phd4_real_exploits.rs:244-297` показывает: злоумышленник с (ПИН, captured account_local_salt) восстанавливает полную bit-equal цепочку anon-IDs **без единого запроса к серверу**. Argon2id брутфорс ПИН на мобильном ~600-800мс/попытка → 6-digit PIN = 10^6 space → ~140 часов на одном CPU либо ~6 часов на GPU ферме (Argon2id resists GPU partially, фактор ~10× → ~22ч на GPU). Для противника уровня D (государственный уровень) это feasible.

**Целевое состояние** (что нужно сделать):

Заменить локальный HKDF на OPRF (слепое вычисление) с 3-of-5 кворумом серверов:

```rust
// Псевдо-код целевой схемы
async fn derive_anon_ids_via_oprf(
    pin_root: &[u8; 32],
    salt: &AccountLocalSalt,
    server_client: &Arc<dyn ServerOprfClient>,
) -> Result<[[u8; 32]; 5], ClientError> {
    // 1. Устройство blind'ит pin_root через umbrella-oprf::client::blind
    let (blinded_request, blind_state) = umbrella_oprf::blind(pin_root.into(), &mut OsRng)?;
    
    // 2. Отправляет blinded request к 3 of 5 серверам параллельно
    let mut server_evaluations = Vec::with_capacity(3);
    for server_id in 1..=5u8 {
        if server_evaluations.len() >= 3 { break; }
        match server_client.evaluate_anon_id(server_id, &blinded_request).await {
            Ok(eval) => server_evaluations.push((WitnessIndex::new(server_id)?, eval)),
            Err(_) => continue,
        }
    }
    if server_evaluations.len() < 3 {
        return Err(ClientError::Network("fewer than 3 OPRF servers responded".into()));
    }
    
    // 3. Threshold combine 3-of-5 — Lagrange interpolation over Ristretto255 points
    //    (использует существующий umbrella_oprf::threshold_combine)
    let combined_eval = umbrella_oprf::threshold_combine(
        &server_evaluations,
        ThresholdConfig::default(),
    )?;
    
    // 4. Устройство unblind'ит результат через blind_state.finalize
    let oprf_output = blind_state.finalize(combined_eval, pin_root.into())?;
    
    // 5. Derive 5 anon_ids из oprf_output через HKDF (теперь это derivable
    //    только если у адверсаря есть quorum 3-of-5 server_keys — что 
    //    защищает confidential anon-IDs)
    let anon_ids = anonymous_id::derive_all_anonymous_ids(oprf_output.as_bytes())?;
    Ok(anon_ids)
}
```

**Что менять (детально):**

1. **Backend coordination первое:**
   - Согласовать с командой сервера OPRF endpoint протокол: `POST /v1/oprf/evaluate_anon_id` принимает `BlindedRequest` (32 байта Ristretto255 point) + `server_id` + attestation token, возвращает `ServerEvaluation` (32 байта Ristretto255 point)
   - Server-side: каждый из 5 Sealed Servers держит свою долю Shamir polynomial OPRF key `k_i = f(server_id_i)` где `f(0) = master_oprf_key`. Server evaluation = `BlindedRequest * k_i`.
   - DKG для master_oprf_key должна происходить при cluster startup (FROST ceremony либо аналогичная).

2. **Client-side изменения в `distributed_identity_client.rs`:**
   - Добавить trait `ServerOprfClient: Send + Sync` с методом `async fn evaluate_anon_id(&self, server_id: u8, blinded: &BlindedRequest) -> Result<ServerEvaluation, ClientError>`.
   - Добавить `MockServerOprfCluster` для тестов с Shamir-split master_oprf_key и server_id-bound evaluations.
   - Заменить локальную HKDF цепочку в `bootstrap_account` на async-вызов OPRF на 3 of 5 серверов + `umbrella_oprf::threshold_combine` для combine.
   - Output OPRF (32-байтный Scalar либо Point) используется как seed для `derive_all_anonymous_ids`.
   - Bootstrap теперь требует server_client argument либо async runtime — обновить FFI вызовы.

3. **`crates/umbrella-ffi/src/export/onboarding.rs`:**
   - `create_account_with_pin` метод сейчас sync — нужно сделать async через `#[uniffi::export(async_runtime = "tokio")]`.
   - Либо: оставить sync facade в FFI который внутри блокирует на tokio runtime (паттерн как в `umbrella-client::attestation::unwrap_sealing.rs` есть пример).

4. **Регрессионные тесты:**
   - Existing `attack_phd4_f2_anon_ids_independently_derivable_from_pin_plus_salt` (в `crates/umbrella-tests/tests/attack_phd4_real_exploits.rs`) должен **начать падать** после fix — адверсарь с (ПИН + salt) без 3-of-5 server queries больше не может derive anon_ids. Это **сигнал что exploit closed**.
   - Добавить positive test: «3-of-5 OPRF threshold combine yields same anon_ids regardless of which 3 servers responded» — analog `lagrange_reconstruction_yields_same_master_for_different_quora` test.
   - Negative test: «2-of-5 servers недостаточно — bootstrap fails с InsufficientOprfQuorum».
   - Negative test: «adversary с k-1 = 2 server OPRF keys не может recover anon_ids» (использовать MockServerOprfCluster с раскрытыми 2 keys, симулировать атаку).

5. **Обновить документацию:**
   - `docs/audits/phd-b-final-consolidation-2026-05-18.md` — отметить F-2 закрытой
   - Memory `project_phd_b_pass5_complete.md` — отметить F-2 closed
   - Создать commit-handoff doc для backend team

**Существующий API для использования:**
- `umbrella_oprf::client::blind(input, rng)` → `(BlindedRequest, BlindState)`
- `umbrella_oprf::client::finalize(state, server_eval, input)` → `OprfOutput`
- `umbrella_oprf::threshold_combine(&[(WitnessIndex, ServerEvaluation); 3], config)` → `Result<ServerEvaluation, OprfError>`
- `umbrella_oprf::shamir_split_for_testing(k: Scalar, config, rng)` → `[(WitnessIndex, Scalar); 5]` — для MockServerOprfCluster

**Сложность:** ~6-8 часов client-side работа + согласование с backend team. Если backend OPRF endpoint ещё не существует — можно реализовать клиентскую часть с MockServerOprfCluster и пометить production-path как fail-closed до backend готовности.

**Время оценки:**
- ~2 часа: добавить trait + Mock + структуру
- ~3 часа: переписать `bootstrap_account` на async OPRF flow
- ~2 часа: регрессионные тесты (positive + 2 negative)
- ~1 час: документация + commit

---

### Track B — Серьёзные находки HW Keystore кластер (M-FINAL-1 v1.2.x, ~20-30 часов)

5 связанных находок — все про подключение защищённого чипа (TEE = Trusted Execution Environment) в production пути signing операций. Сейчас все signing идёт через `core.identity.sign(...)` который использует эфемерное (одноразовое) семя синтезированное в `crates/umbrella-client/src/core.rs:421-424` (раскрытие M-FINAL-1).

#### F-IDENT-1 HIGH/HONEST GAP — InMemoryKeyStore — единственная реализация KeyStore

**Файл:** `crates/umbrella-identity/src/keystore.rs`

**Состояние:** `InMemoryKeyStore` — единственная impl `KeyStore` trait в репозитории. Документировано как «test-only» + «НЕ для production» в module-level doc-comment. Но в коде нет реальной альтернативы; production users либо implement KeyStore сами через FFI bridge, либо используют InMemoryKeyStore в production (footgun).

**Целевое состояние:** Создать `HwBackedKeyStore: KeyStore` в `umbrella-client/src/keystore/hw_backed.rs`:
- Все операции с identity_sk routed через `PersistentKeyStoreCallback::sign_identity(handle, data)` 
- Native iOS реализация callback: `SecKeyCopyPublicKey` + `SecKeyCreateSignature` через Secure Enclave
- Native Android: `KeyStore.getKey(alias)` + `Signature.getInstance("Ed25519").sign(data)` через StrongBox
- Identity_sk **физически не существует** в Rust heap — handle ссылается на TEE-resident key

**Сложность:** ~10-15 часов (требует FFI integration с native iOS/Android).

#### F-IDENT-2 HIGH — seed живёт в keystore heap для lifetime

**Файл:** `crates/umbrella-identity/src/keystore.rs`

**Состояние:** `InMemoryKeyStore.seed: IdentitySeed` живёт в process heap всю lifetime keystore. Даже с seed `Box<[u8; 64]>` heap-resident (R7-3 closure), оно persists для keystore lifetime; `add_device` re-derives `DeviceKey::derive(&self.seed, ...)`. Adversary с process memory access регенерирует **все** device keys без individual device_sk leaks.

**Целевое состояние:** Mitigation через HwBackedKeyStore из F-IDENT-1 — production не материализует seed в process heap; только attestation + signing operations на opaque handles. Эти 2 находки связаны и закрываются одним рефакторингом.

**Сложность:** включено в F-IDENT-1 (тот же кластер).

#### F-CLIENT-HW-1 HIGH/HONEST GAP — 0 production signing operations route через core.hw_callback

**Файл:** `crates/umbrella-client/src/keystore/hw_callback.rs` + `crates/umbrella-client/src/core.rs:307-442`

**Состояние:** `PersistentKeyStoreCallback` interface определён, `ClientCore::new_with_hw_callback` принимает `Arc<dyn PersistentKeyStoreCallback>`, `has_hw_identity()` accessor существует. Но cross-workspace grep `core.hw_callback.sign_identity` показывает 0 production callsites. Все production signing через `core.identity.sign(...)` (эфемерное seed). TEE pathway dormant.

**M-FINAL-1 disclosure в `core.rs:407-424`:** Когда `new_with_hw_callback` invoked, verifying-key из `bootstrap_hw_identity` **дискардится** (`let (handle, _verifying_key_placeholder) = ...`) и ClientCore синтезирует **отдельное эфемерное** `IdentityKey` из one-shot seed:
```rust
let ephemeral_seed = IdentitySeed::generate(&mut rand_core::OsRng, MnemonicLanguage::English);
let identity = Arc::new(IdentityKey::derive(&ephemeral_seed, 0)?);
drop(ephemeral_seed); // explicit zeroize-on-drop
```

`core.identity` (используется для **всех** production signing) НЕ соответствует TEE-resident `hw_identity_handle`.

**Целевое состояние:**

1. **Refactor `core.identity: Arc<IdentityKey>` → `Option<Arc<IdentityKey>>`**
   - Когда есть `hw_callback`, `core.identity = None` (no ephemeral seed)
   - Когда нет `hw_callback` (тесты, transition), `core.identity = Some(...)` legacy path

2. **Все signing paths проверяют `core.has_hw_identity()`:**
   - `crates/umbrella-mls/src/signer.rs` `UmbrellaIdentitySigner` + `UmbrellaDeviceSigner`
   - `crates/umbrella-sealed-sender/src/lib.rs` sealed-sender пути
   - `crates/umbrella-backup/src/cloud_wrap/signed_request.rs` unwrap-request signing
   - Если `hw_callback` есть → `core.hw_callback.sign_identity(handle, data).await?`
   - Иначе → `core.identity.as_ref().ok_or(NoIdentityKey)?.sign(data)?` (legacy)

3. **Добавить `verifying_key` метод в `PersistentKeyStoreCallback` trait:**
```rust
trait PersistentKeyStoreCallback: Send + Sync {
    fn sign_identity(&self, handle: &HwKeyHandle, data: &[u8]) -> Result<[u8; 64], HwKeystoreError>;
    fn sign_device(&self, handle: &HwKeyHandle, data: &[u8]) -> Result<[u8; 64], HwKeystoreError>;
    /// NEW: возвращает 32-byte Ed25519 verifying key для TEE-resident identity
    fn verifying_key(&self, handle: &HwKeyHandle) -> Result<[u8; 32], HwKeystoreError>;
}
```

4. **Update `bootstrap_hw_identity`:** возвращает real verifying-key вместо `[0u8; 32]` placeholder.

**Сложность:** ~8-12 часов.

#### F-CLIENT-HW-2 MEDIUM — bootstrap_hw_identity returns [0u8; 32] verifying-key placeholder

**Файл:** `crates/umbrella-client/src/keystore/hw_callback.rs:511-525`

**Состояние:** Closure F-CLIENT-HW-1 — downstream consequence. Закрывается тем же refactor'ом.

**Сложность:** включено в F-CLIENT-HW-1 (~30 минут дополнительно к F-CLIENT-HW-1 refactor).

#### F-4 HIGH carry-over — R21 attack test bypasses transport/sign/quorum

**Файл:** `crates/umbrella-client/tests/attack_r21_duress_pin_deletes_account.rs:28-115`

**Состояние:** Тест использует `b"share-encrypted-bytes".to_vec()` literal placeholder вместо real encrypted FROST share. Никакой transport/network layer; нет threshold-sign verification для UNRECOVERABLE_DELETE command. Тест happy-path counters/flags.

**Целевое состояние:** Построить real client-server test rig:
- 5 separate `AccountState` instances
- Mocked transport requiring FROST signature on UNRECOVERABLE_DELETE
- Real Shamir polynomial shares через `umbrella_threshold_identity::dkg`
- Negative test: adversary sends UNRECOVERABLE_DELETE без 3-of-5 FROST signature → cluster rejects

**Сложность:** ~4-6 часов.

---

### Track C — Серьёзный формальный + кластер тавтологических лемм (~16-24 часа, post-1.0.0)

6 находок в крейте `umbrella-formal-verification` — все про refactor `.spthy` моделей.

#### F-MLS-MODEL-1 HIGH formal-claim-gap — mls_ed25519.spthy 3 тавтологические леммы

**Файл:** `crates/umbrella-formal-verification/models/mls_ed25519.spthy`

**Состояние:** 3 главные леммы (`external_operations_disabled`, `etk_split_brain_prevented`, `ed25519_only_whitelist`) тавтологичны. Lemma `etk_split_brain_prevented` доказывает только determinism hash, не ECDSA malleability defense. Модель НЕ содержит символов функции ECDSA, несмотря на цитирование атаки Cremers-Gellert-Wiesmaier-Zhao eprint 2025/229.

**Целевое состояние:**

1. **Добавить ECDSA function symbols + malleability equation:**
```spthy
// Тавтологичный было — заменяется реальной малеаб-семантикой
functions: ecdsa_sign/3 [private], ecdsa_verify/3, ecdsa_repack/2
equations:
    // Стандарт ECDSA: malleable signatures — два байт-различных подписи verify одинаково
    ecdsa_verify(ecdsa_sign(sk, m, r), m, ecdsa_pk(sk)) = true,
    ecdsa_verify(ecdsa_repack(ecdsa_sign(sk, m, r), r2), m, ecdsa_pk(sk)) = true,
    ecdsa_sign(sk, m, r) <> ecdsa_repack(ecdsa_sign(sk, m, r), r2)  // байт-различны
```

2. **Re-state `etk_split_brain_prevented`** как substantive claim:
```spthy
lemma etk_split_brain_prevented_substantive:
    "All sk m sig1 sig2 #i #j.
        Sign(sk, m, sig1) @ i & Sign(sk, m, sig2) @ j & not(sig1 = sig2)
        ==>
        // Под Ed25519 SUF-CMA: невозможно два байт-различных подписи на same m,sk
        not Ex(SignatureScheme.Ed25519) @ k & k < i & k < j"
```

3. **Make `external_operations_disabled` reachable** — добавить adversary rule attempting external commit с reject path.

4. **Make `ed25519_only_whitelist` non-trivial** — separate CreateGroup vs Whitelisted action emissions across rules.

**Сложность:** ~4-6 часов формального моделирования.

#### 5 MEDIUM тавтологических лемм cluster

**Файлы:**
- `kt_v1_self_monitoring.spthy` — 3 тавтологии вида `not(A=B) ⟹ not(B=A)`
- `kt_v2_self_monitoring.spthy` — те же + структурная истинность `'absent' ≠ 'present'`
- `sframe_rfc9605.spthy` — 2 of 4 (dtls_identity_binding + kid_uniqueness)
- `downgrade_resistance.spthy` — 3 of 5 (default_ciphersuite + no_silent_fallback + adversary_strip)
- `type_safe_enforcement.spthy` — 3 of 4 (linear-fact chaining + mode-gated + Fr semantics)

**Целевое состояние:** Заменить тавтологии на causal claims вида:
```spthy
// Тавтология (текущее):
"... not(observed = local) ==> not(local = observed)"  // commutativity

// Substantive (целевое):
"All A observed local #i.
    SelfMonitor(A, observed, local) @ i & not(observed = local)
    ==>
    Ex orig #j. AdversarySubstitute(A, orig, observed) @ j & j < i"
```

**Сложность:** ~3-4 часа на каждую модель × 5 моделей = ~15-20 часов.

---

### Track D — Высокий с честным gap (v1.1.x roadmap, outside PhD-B scope)

#### F-CLIENT-FACADE-1 HIGH/HONEST GAP — все facade methods Block 7.2 stubs

**Файлы:** `crates/umbrella-client/src/facade/{chat_common,cloud_chat,secret_chat}.rs`

**Состояние:** `send_mls_text → Ok(MessageId([0u8; 16]))`, `fetch_inbox → Ok(Vec::new())`, `add_participant → Ok(())`. Documented Block 7.2 stub state. Production transport fail-closed at `ClientCore::new_with_http2` — cannot actually deploy.

**Целевое состояние:** Block 7.4 milestone wire-up:
- `send_mls_text` → реальный MLS encrypt + padding + sealed-sender wrap + Postman queue submit
- `fetch_inbox` → реальный Postman pull + sealed-sender unseal + MLS decrypt + ordering
- `add_participant` / `remove_participant` → MLS commit operations + key delivery

**Сложность:** outside PhD-B scope — это product roadmap milestone. Не PhD remediation. Можно отложить документально, отметив что F-CLIENT-FACADE-1 трекается как Block 7.4.

---

### Track E — Dudect investigation cluster (~2-4 часа, v1.0.x)

3 находки про methodology recalibration после Pass 5 1M-sample run:

#### F-DUDECT-HKDF-BORDERLINE-1 MEDIUM — kdf::hkdf_sha256<32> |t|=6.79

**Файл:** `crates/umbrella-tests/tests/dudect_constant_time.rs` (Site 2)

**Цель:** Re-run с bounded pool pattern (analog Site 6 RowCipher 32 fixtures cache-hot symmetry) + Linux CI cross-platform confirmation. Если |t| > 4.5 persists → upstream `hmac::Hmac<sha2::Sha256>` investigation.

#### F-DUDECT-METHODOLOGY-1 MEDIUM/INFO — sample-saturation artifact на sub-100ns operations

**Цель:** Adjust in-block guard threshold per operation timing scale OR apply cache-bounded pool pattern всем sub-100ns operations sites. Recalibrate so что upstream subtle 2.6 baseline и padding_strip не дают false-positive panics.

#### F-DUDECT-PADDING-OBSERVATION-1 MEDIUM/INFO — padding_strip |t|=20.0 на 1M samples

**Цель:** Same as methodology — apply bounded pool + ARMv8 prefetcher state investigation.

**Сложность:** ~2-4 часа всего.

---

## Приоритизация для следующих сессий

**Сессия 1 (рекомендуемый порядок):**
1. **Track A — F-2** (последняя CRITICAL, ~6-8 часов)
   - Client-side OPRF integration (если backend ещё нет — Mock + fail-closed production path)
   - Регрессионные тесты
   - Один коммит в main

**Сессия 2:**
2. **Track B — HW Keystore cluster** (F-CLIENT-HW-1 + F-CLIENT-HW-2 + F-IDENT-1 + F-IDENT-2, ~12-15 часов)
   - core.identity: Option<Arc<IdentityKey>>
   - signing paths route через hw_callback
   - HwBackedKeyStore impl
   - verifying_key method добавлен
   - Один либо два коммита

**Сессия 3:**
3. **Track B завершение — F-4 R21 test rebuild** (~4-6 часов)

**Сессия 4:**
4. **Track C — Formal models cluster** (~16-24 часа, можно разбить на 6 сессий по модели)
   - mls_ed25519.spthy first (HIGH severity)
   - 5 MEDIUM tautology cluster в любом порядке

**Сессия 5:**
5. **Track E — Dudect investigation** (~2-4 часа)

**Сессия 6:**
6. **Track D — F-CLIENT-FACADE-1** (Block 7.4 milestone — outside PhD scope, защоtать как roadmap item)

---

## Правила работы из памяти — ОБЯЗАТЕЛЬНЫ

### Активный режим аудита (`feedback_active_audit_mode`)

Каждое CRITICAL/HIGH closure ДОЛЖНО иметь:
- Working regression test, demonstrating exploit closure (NOT просто doc-update)
- Existing attack demonstrator должен начать падать после fix (signal что exploit closed) либо sustained как class-level regression guard с обновлённым docstring
- Реальный код менять, не только comments либо docs

### Реальные эксплойты не paperwork (`feedback_real_not_paperwork`)

Third recurrence enforcement: каждое CRITICAL finding должно либо:
- Демонстрировать working exploit с измеренным outcome (биты восстановлены, запросы нужно, байты утекли)
- ЛИБО показывать unexploitable С ИЗМЕРЕННЫМИ ЧИСЛАМИ

После fix attack_phd4_* тесты:
- F-1, F-2 паттерны — должны падать (положительная Lagrange property liey OPRF threshold demonstrate)
- F-FFI-2 — sustains as class-level regression guard (hex::encode + MlockedSecret паттерн фундаментально небезопасен независимо от FFI exposure)

### 6/6 self-check (`feedback_phd_vs_a_level_distinguisher`)

Применить **перед каждым commit ремедиации**:

1. **Findings count** — N/A для remediation (это не audit pass).
2. **Test naming honesty** — `attack_*` для реальных атак (class-level regression guards), `verify_*` либо `decision_logic_*` для behavioral verifications. После fix положительные property tests называются `*_property_*` либо `*_closure_regression_*`.
3. **Tamarin/ProVerif** — для F-MLS-MODEL-1 + 5 tautology cluster, ОБЯЗАТЕЛЬНО запустить Tamarin локально chec после refactor lemmas. Не commit'ить если Tamarin не verify'ит новые substantive lemmas.
4. **Dudect** — для F-DUDECT cluster, измерить после bounded-pool fix.
5. **Reduction sketches** — для каждого fix указать concrete numbers в commit message (bits leaked closed, queries needed, computational bound).
6. **Literature** — cite RFC / paper для каждого crypto choice.

Если 2+ checks fail = НЕ заявлять PhD в commit. Это уровень A замаскированный под PhD.

### Полный PhD либо handoff (`feedback_phd_no_partial`)

Только full PhD-B 6/6 self-check либо handoff в свежую сессию. «Частичный PhD-аппарат» = провал.

Для remediation: applicable только #2 и #5 из 6 (test naming + concrete numbers). Остальные N/A для fixes.

### Лимит контекста 60% (`feedback_context_60pct`)

Работаем до 60% контекста. При приближении либо прогнозе overrun — предупредить и сделать handoff. Не пытаться «дотянуть».

### Прямые коммиты в main (`feedback_direct_to_main`)

Один блок = один коммит в main без feature branches. `finishing-a-development-branch` skill не применим. Автор Kirill Abramov. **БЕЗ** Co-Authored-By: Claude в commit messages (правило пользователя).

### Простой русский (`feedback_simple_language`)

При обсуждении с пользователем объяснять простым русским языком, технические термины с пояснением в скобках. В коде и документах — полные термины на английском.

### Push policy

НЕ делать `git push` без явной просьбы пользователя. Сейчас 11 локальных коммитов не отправлены.

---

## Файлы для чтения первыми в новом чате

В таком порядке:

1. **Команды git:**
   ```bash
   git -C "/Users/daniel/Documents/Projects/Messenger/Umbrella Protocol" log --oneline -15
   git -C "/Users/daniel/Documents/Projects/Messenger/Umbrella Protocol" status
   ```
   Подтвердить HEAD = `b48191b7` и чистоту рабочей копии.

2. **Этот handoff** — `docs/superpowers/handoffs/2026-05-18-phd-b-remediation-continuation-handoff.md` (полный план).

3. **Финальный сводный отчёт Pass 5** — `docs/audits/phd-b-final-consolidation-2026-05-18.md` (600 строк): таблица всех 17 находок с severity / status / file paths + remediation roadmap §6 + ship/no-ship decisions §3.

4. **Memory:**
   - `~/.claude/projects/-Users-daniel-Documents-Projects-Messenger-Umbrella-Protocol/memory/MEMORY.md` (index)
   - `memory/project_phd_b_pass5_complete.md` — Pass 5 closure record с tracking каждой находки (5 closed, 12 open)
   - `memory/feedback_real_not_paperwork.md`
   - `memory/feedback_phd_no_partial.md`
   - `memory/feedback_phd_vs_a_level_distinguisher.md`
   - `memory/feedback_direct_to_main.md`
   - `memory/feedback_context_60pct.md`
   - `memory/feedback_simple_language.md`

5. **Для F-2 fix (рекомендую первое):**
   - `crates/umbrella-client/src/keystore/distributed_identity_client.rs` — current bootstrap_account (строки 232-287)
   - `crates/umbrella-oprf/src/threshold.rs` — `threshold_combine` + `shamir_split_for_testing` API
   - `crates/umbrella-oprf/src/client.rs` — `blind` + `finalize` API
   - `crates/umbrella-oprf/src/lib.rs` — public exports
   - `crates/umbrella-tests/tests/attack_phd4_real_exploits.rs:244-297` — F-2 exploit demonstrator

6. **Для F-MLS-MODEL-1 fix (Track C):**
   - `crates/umbrella-formal-verification/models/mls_ed25519.spthy` (всё, ~330 строк)
   - `crates/umbrella-formal-verification/models/multi_device_authorization.spthy` — exemplar 13 substantive lemmas для образца
   - `crates/umbrella-formal-verification/models/hybrid_signature_and_mode.spthy` — exemplar AND-mode 3 substantive lemmas

---

## Стратегия бюджета контекста

Свежая сессия 1M tokens (Opus 4.7) → 60% лимит = ~600K tokens budget.

**Для F-2 fix (Track A) — реалистично уместится в одну сессию:**
- 10% — чтение handoff + Pass 5 report + memory + OPRF API
- 30% — реализация client-side OPRF integration (trait + MockServerOprfCluster + async refactor bootstrap_account)
- 20% — регрессионные тесты (3 теста: positive Lagrange + 2 negative)
- 15% — обновление документации + memory + handoff
- 5% — cargo check + cargo test + commit
- 20% — buffer на отладку + edge cases

**Для Track B HW Keystore cluster — отдельная сессия:**
- Более сложный refactor затрагивающий 4 крейта (umbrella-client + umbrella-mls + umbrella-sealed-sender + umbrella-backup)
- Реалистично нужно разбить на 2 сессии: core.identity refactor + signing paths wire-up в Session 1; HwBackedKeyStore impl + tests в Session 2.

**Для Track C Formal models — разбить на 6 сессий:**
- Каждая модель ~3-4 часа формального моделирования
- Tamarin compile + verify времени-затратное; разумно одна модель за сессию
- mls_ed25519.spthy первое (HIGH severity)

**Если бюджет не позволяет полный fix:**
- НЕ пытаться «дотянуть частично»
- Закрыть consistent логический объём (например, добавить trait + Mock но не reimplement bootstrap)
- Сделать честный handoff describing где остановились + что осталось

---

## Условия остановки и handoff

- **Достиг 60% контекста** — закоммитить состояние и сделать handoff.
- **Если 6/6 self-check недостижим за оставшийся бюджет** — закрыть осмысленную часть, остальное в handoff.
- **Если fix ломает existing tests непредвиденным образом** — закоммитить состояние «вот что сломалось» + handoff.
- **Если backend OPRF endpoint не существует** для F-2 — реализовать client-side + Mock; production path должен быть fail-closed; документировать что backend integration deferred.
- **Если Tamarin не verify'ит new lemmas в Track C** — НЕ коммитить с пропавшим proof. Исправить либо откатиться + handoff с описанием.

---

## Минимум deliverables для каждой track

### Track A — F-2

1. `crates/umbrella-client/src/keystore/distributed_identity_client.rs` — заменён локальный HKDF на OPRF flow
2. New trait `ServerOprfClient` + `MockServerOprfCluster` (с Shamir-split master_key)
3. `bootstrap_account` async через OPRF threshold combine
4. Существующий `attack_phd4_f2_anon_ids_independently_derivable_from_pin_plus_salt` тест transitions PASS → FAIL (signal exploit closed)
5. Новый positive test: 3-of-5 OPRF threshold yields same anon_ids regardless of quorum
6. Новый negative test: 2-of-5 OPRF servers недостаточно
7. Новый negative test: adversary с k-1=2 server OPRF keys не может recover anon_ids
8. `cargo check --workspace` + `cargo test -p umbrella-client` + `cargo test -p umbrella-tests --test attack_phd4_real_exploits` зелёные
9. Один коммит в main `fix(client): F-2 CRITICAL closure — server-side OPRF replaces local HKDF for anon-ID derivation`
10. Memory update: `project_phd_b_pass5_complete.md` отметить F-2 closed

### Track B — HW Keystore cluster (после Track A)

1. `core.identity: Arc<IdentityKey>` → `Option<Arc<IdentityKey>>`
2. Удалить ephemeral seed синтез в `core.rs:421-424`
3. Все signing paths route через `core.hw_callback.sign_identity(handle, data)` если есть
4. `PersistentKeyStoreCallback::verifying_key(handle)` метод добавлен
5. `bootstrap_hw_identity` returns real verifying-key
6. Новый `HwBackedKeyStore: KeyStore` impl
7. Регрессионные тесты: process memory capture не recovers identity_sk; signing routes through hw_callback verified
8. cargo check + tests + один-два коммита

### Track C — Formal models (один коммит per модель)

1. Refactor lemma — substantive form вместо тавтологии
2. Tamarin compile + verify clean
3. Документация: docstring update в модели «substantive после Pass 5 closure»
4. spec_version bump per F-59 защита pattern
5. Один коммит per модель `fix(formal): F-XXX-MODEL-1 MEDIUM closure — substantive lemma replaces tautology`

### Track E — Dudect cluster

1. Bounded-pool refactor для Sites 2/3/4 (32 fixtures cache-hot symmetry)
2. Re-run 1M samples — все 8 CT-критичных primitives CLEAN strict 4.5
3. Methodology disclaimer в `crates/umbrella-tests/src/dudect.rs` про per-operation-timing-tier thresholds
4. cargo test зелёный без panics
5. Один коммит

---

## Как начать в новом чате

1. Открыть Claude Code в директории `/Users/daniel/Documents/Projects/Messenger/Umbrella Protocol`
2. Скопировать всё содержимое раздела «Контекст проекта» этого handoff (от заголовка через все Tracks + Правила) в первое сообщение нового чата
3. Сказать: «Начни с Track A — F-2. Применяй 6 self-check rules. Соблюдай feedback_real_not_paperwork. Лимит контекста 60%.»

Либо проще: «Прочитай `docs/superpowers/handoffs/2026-05-18-phd-b-remediation-continuation-handoff.md` и закрой все оставшиеся 12 находок по плану.»

---

## Текущая фиксация (для проверки)

- HEAD: `b48191b7`
- Локальных коммитов: 11 (не push'ed)
- Открытых находок: 12
- Закрытых в текущей сессии: 5 (F-FFI-2, F-1, F-3, F-IDENT-37, F-MLS-1)
- Workspace baseline: 2080+ tests + новые regression guards
- Ship status v1.0.0: **NOT READY** пока F-2 открыта (последняя CRITICAL)

После закрытия F-2 → ship-ready v1.0.0; остальные 11 находок accepted для post-1.0.0 cluster closures.

End of handoff.
