# Changelog

[English](#english) | [Русский](#русский)

## English

### 3.0.0 — 2026-05-20

Release ceremony consolidating post-1.1.0 hardening:

Added:
- Max Ratchet v3 (default-on aggressive DH + 5-minute timer rekey + PQ extension every 3rd commit + SPQR HMAC deniable authentication); see `docs/audits/max-ratchet-deniability-spec-2026-05-20.md` + `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`
- `umbrella-discovery` crate (Round 7: OPRF-PSI + `@username` lookup with KT bind; 38 D-1..D-8 attack tests)
- `umbrella-threshold-identity` crate (Round 6: FROST-Ed25519 DKG, PIN/Argon2id model, duress detection, time-lock recovery)
- 2 fuzz targets: `max_ratchet_envelope_{decode,roundtrip}.rs`
- 5 Tamarin models: `aggressive_dh_pcs`, `spqr_deniability`, `discovery`, `sealed_servers_threshold_3of5`, `sealed_servers_threshold_universal`
- Public wire-contract `docs/spec/discovery-integration.md`
- Backend integration contract `docs/integration/gateway-svc-contract.md`

Changed:
- Workspace package version: 1.1.0 → 3.0.0 (commit `1ee8dbb3`)
- F-CLIENT-FACADE-1 MILESTONE 10/10 closed (12 sub-sessions; commit `9417096b`)
- PhD-B Pass 5 remediation: 18 findings closed (20 commits `471e7928..23eda73a`)
- `ClientCore.identity`: `Option<Arc<IdentityKey>>` and `None` on hw bootstrap path; M-FINAL-1 closed via Pass 5 commit `e7b034ff` (F-CLIENT-HW-1)
- 6 Tamarin model tautologies replaced with substantive multi-rule correspondence lemmas
- 3 dudect measurement-artefact findings closed via bounded-pool pattern at sub-100 ns sites; F-DUDECT-HKDF-BORDERLINE-1 methodology documented в `docs/audits/dudect-saturation-methodology-2026-05-19.md`

Security:
- 0 BLOCKER + 0 MAJOR (M-FINAL-1 closed) + 1 MINOR-5 carry-over (FFI `with_http_cluster`)
- 14 Tamarin models verified under `tamarin-prover 1.12.0`; 4 ProVerif models (unchanged)
- Workspace baseline 2179+ release-mode tests (post-Round 7 floor; post-1.1.0 series adds further)

Verification: see `docs/security/release-notes-v3.0.0.md` § Verification.

### Post-1.1.0 Max Ratchet v3 — 2026-05-20

Added a default-on aggressive DH + 5-minute timer rekey + post-quantum
extension every third commit + SPQR HMAC deniable authentication layer
on top of every Umbrella v3 group.

Implementation modules in `crates/umbrella-mls/src/max_ratchet/`
(`config.rs`, `counter.rs`, `timer.rs`, `spqr.rs`, `group.rs`, `state.rs`,
`envelope.rs`). Wire format uses an in-band v3 marker (`0xFF`) inside
`ClientPayload::SendMessage.ciphertext`; backward read-compat with
existing v2 readers; no gateway-svc proto changes.

Coverage:

- 36 unit tests across max_ratchet modules.
- 10 baseline + 5 active-mode security claim integration tests in
  `crates/umbrella-client/tests/facade_max_ratchet_v3.rs`.
- 6 PQ integration tests (real X-Wing combine into SPQR keying) in
  `crates/umbrella-mls/tests/test_max_ratchet_pq_real.rs`.
- 5 proptest property-based fuzz tests + 5.67M libFuzzer iterations in
  `crates/umbrella-fuzz/fuzz/fuzz_targets/max_ratchet_envelope_*.rs`.
- Criterion benchmarks on Apple M2: 27 μs baseline encrypt, 140 μs
  force_rekey, 0.26 μs SPQR HMAC; total max_ratchet 167.36 μs.
- Tamarin formal models for SPQR deniability + aggressive DH PCS
  (Task 5 PhD-B): `crates/umbrella-formal-verification/models/
  spqr_deniability.spthy` + `aggressive_dh_pcs.spthy`.
- Local dudect 1M-sample constant-time evidence for `verify_hmac`
  (|t|=0.000 perfect on Apple M2 single-thread; Task 4 PhD-B).
- Forward-secrecy Tamarin lemma in `aggressive_dh_pcs.spthy`
  (post-fix: explicit `Ex` binding closes wellformedness gap).

Specification + evidence:

- `docs/audits/max-ratchet-deniability-spec-2026-05-20.md` — 10/10
  acceptance criteria.
- `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md` — per-claim
  test → measured outcome → numerical bound matrix per
  `feedback_real_not_paperwork`.

Carry-over: external cryptographic review (Cure53 / NCC / Trail of Bits)
remains the standard pre-ship process.

### Post-1.1.0 F-CLIENT-FACADE-1 MILESTONE 10/10 closure - 2026-05-19

Closed F-CLIENT-FACADE-1 across 12 sub-sessions (1-10f):

- session 1: WebSocket transport + mock gateway + 14 contract tests.
- session 2: QUIC transport (quinn) + auto-fallback dispatcher + 17 tests.
- session 3: `send_text` wired end-to-end through `GatewayConnection`.
- session 4: `fetch_inbox` wired via `IncomingMessage` envelope drain.
- session 5: real MLS group create + add_member.
- session 6 / 6c: `cloud_sync_history` 3-of-5 unwrap + Welcome
  distribution + Cloud at-rest dual-write.
- session 7: SecretChat sealed-sender envelope wrap/unwrap.
- session 8a / 8b / 8c1-3: on-demand KT self-monitor + 3-of-5 witness
  threshold + `SignedEpochRoot` production wire codec.
- session 9 / 9a-9f: `rotate_identity_full` HW-callback orchestration +
  KT identity rotation wire codec + atomic keystore slot swap.
- session 10 / 10a-10f: TURN allocation + DTLS / SRTP keying +
  SFrame multi-party media + state-machine transitions + webrtc-srtp
  Context wire-up at facade + `initiate_device_transfer`
  HW-signing+publish orchestration.

Integration contract documented at `docs/integration/gateway-svc-contract.md`.
Public FFI bootstrap remains gated on real platform attestation,
mobile bridges, and server deployment integration (separate milestone).

### Post-1.1.0 PhD-B Pass 5 remediation closure - 2026-05-19

Closed 18 PhD-B Pass 5 findings across 20 commits on `main` between
`471e7928` and `23eda73a`:

- 4 CRITICAL ship-blockers (F-1 Shamir Lagrange / F-2 server-side OPRF /
  F-3 R23 honest naming / F-FFI-2 session-handle pattern).
- 5 HIGH findings (F-4 R21 FROST 3-of-5 / F-MLS-1 compile-time gate on
  `UmbrellaXWingProvider` / F-CLIENT-HW-1 + F-IDENT-1 + F-IDENT-2 hw
  bootstrap path closes M-FINAL-1).
- 6 formal-model tautologies in `mls_ed25519.spthy`,
  `kt_v1_self_monitoring.spthy`, `kt_v2_self_monitoring.spthy`,
  `sframe_rfc9605.spthy`, `downgrade_resistance.spthy`, and
  `type_safe_enforcement.spthy` replaced with substantive multi-rule
  correspondence lemmas.
- 3 dudect measurement-artifact findings closed via bounded-pool
  pattern at sub-100 ns sites; F-DUDECT-HKDF-BORDERLINE-1 methodology
  documented in `docs/audits/dudect-saturation-methodology-2026-05-19.md`.

M-FINAL-1 from the 2026-05-18 independent review is therefore closed.
`ClientCore.identity` is `Option<Arc<IdentityKey>>` and the hw bootstrap
path no longer materialises ephemeral identity_sk. Consolidated report:
`docs/audits/phd-b-pass5-remediation-2026-05-19.md`.

### Post-1.1.0 PhD-B Round 7 discovery merge - 2026-05-18

Round 7 PhD-B audit landed:

- New crate `umbrella-discovery` (~5000 LoC) — OPRF-PSI for phone-number
  intersection and `@username → device_pubkey` lookup, both with KT bind
  via `umbrella-kt::verify_inclusion`.
- Threshold 3-of-5 across Sealed Servers (reuses `umbrella-oprf` round-2
  attack-tested primitive).
- Per-query anonymous-id derivation through HKDF.
- Client-side rate-limit + nonce-replay guard.
- 38 D-series attack-regression sub-tests across 8 files.
- Tamarin model `discovery.spthy` (5 main lemmas + 1 exists-trace).
- Wire-contract spec `docs/spec/discovery-integration.md` (229 LoC).

Workspace baseline 2080 → 2179 release-mode tests.

### Post-1.1.0 PhD-B six-round audit closure - 2026-05-18

Audit:

- Merged PR #6 (`84b4d576`): rounds 1-6 of PhD-B level security audit
  against the 1.1.0 codebase.
  - Round 1: hybrid post-quantum PhD audit (8 findings F-PHD-PQ-1..8).
  - Round 2: reality pass (R1-R6 — KyberSlash, MITM, supply-chain,
    offline decrypt, RNG injection, zeroize lldb).
  - Round 3: hedged-encaps closure (Bellare-Hoang-Keelveedhi 2015 pattern).
  - Round 4: device-capture PhD audit (R7-R12; 4 CRITICAL + 3 HIGH).
  - Round 5: device-capture closure (HW keystore callback +
    `MlockedSecret<T>` migration + `IdentitySeed` heap refactor).
  - Round 6: distributed-identity architectural redesign (FROST-Ed25519
    DKG + PIN model + duress + 8 R20-R27 attack tests).
- Independent reviewer verdict: 0 BLOCKER + 1 MAJOR + 3 MINOR.
- 1 MAJOR finding M-FINAL-1: `ClientCore::new_with_hw_callback` still
  synthesises an ephemeral `IdentityKey` via `IdentitySeed::generate`
  for backwards compatibility. The seed is heap-resident, zeroize-on-drop,
  microseconds-wide window. R20 lldb claim "0 identity_sk hits in 2.2 GB"
  applies only to the round-6 `bootstrap_account` flow. Tracked for
  v1.2.x removal.
- Workspace baseline now 2080 release-mode tests (+103 vs 1977 pre-round-6).

Consolidated summary: `docs/audits/ROUND-1-TO-7-SUMMARY.md`.

### Post-1.1.0 memory hygiene hardening - 2026-05-16

Changed:

- BIP-39 and SLIP-0010 derivation now zeroize intermediate entropy, PBKDF2
  seed, HMAC output, fixed 64-byte copies, temporary extended secrets, and
  temporary chain codes after use.
- Sealed Sender `OpenedEnvelope.message` now uses `OpenedMessage`, a
  zeroizing plaintext wrapper, instead of returning a plain `Vec<u8>`.
- Retry backoff jitter now uses the system RNG (`OsRng`) for consistency with
  the rest of the protocol code.

Verification:

- `bip39_derivation_temporaries_are_zeroizing`
- `slip10_derivation_temporaries_are_zeroized`
- `opened_envelope_message_is_zeroizing_wrapper`
- `retry_jitter_uses_system_rng_not_thread_rng`
- `cargo test -p umbrella-identity -p umbrella-client -p umbrella-sealed-sender --all-features --locked`

### Post-1.1.0 dependency monitoring - 2026-05-15

Added:

- Dependabot configuration for the root Cargo workspace, the separate fuzz
  lockfile, and GitHub Actions.
- Daily `dependency-monitor` workflow for root/fuzz RustSec checks,
  cargo-deny policy, PQ/backend boundary checks, and dry-run update reporting.
- Local audit script that prevents removing the monitoring files or turning
  dependency updates into silent `main` changes.
- Public dependency-monitoring document that explains the review-first update
  policy.

### 1.1.0-security-hardening - 2026-05-15

Added:

- Key Transparency split-view hardening: public epoch observations, verifiable
  equivocation evidence, strict observation history, and witness
  non-equivocation memory.
- Privacy-safe KT observation wire format. It excludes account ids, device
  lists, contacts, chats, and message content.
- External RFC 9497 OPRF attack tests for bad wire lengths, invalid points,
  input-size boundaries, and subthreshold evaluation attempts.
- Public release notes and manifest for version 1.1.0.
- Local `hpke-rs 0.6.1` release patch that removes the unused optional libcrux
  HPKE backend from root and fuzz lockfiles.

Changed:

- Workspace package version is now 1.1.0.
- Public documentation now records local KT split-view detection as implemented
  locally, while keeping live witness deployment and live client observation
  exchange as production boundaries.
- Release gates now include the KT split-view hardening checks, local release
  hardening audit, external crypto attack ledger audit, and full workspace test
  run.

Security:

- A locally valid split-view signed by a malicious witness threshold is no
  longer treated as "closed by signatures alone"; the code now exposes
  comparable observations and evidence so clients can detect conflicting
  views.
- Production-facing incomplete paths remain fail-closed instead of silently
  using test-only constructors.
- TLS/SPKI pinning, platform attestation, OPRF, backup, sealed sender,
  downgrade, replay, tamper, and race checks remain covered by local tests and
  documented release boundaries.
- `RUSTSEC-2026-0124` is closed in the checked supply chain: the vulnerable
  optional `libcrux-chacha20poly1305 <0.0.8` path is absent from root and fuzz
  lockfiles instead of being ignored.

Verification:

- `cargo fmt --all -- --check`
- `cargo test --workspace --all-features --locked`
- `bash scripts/audit-protocol-core-attack-gates.sh`
- `bash scripts/audit-local-release-hardening.sh ...`
- `bash scripts/audit-public-access-notices.sh`
- `bash scripts/audit-pq-backend-policy.sh`
- `cargo audit -f crates/umbrella-fuzz/fuzz/Cargo.lock`

### Documentation refresh - 2026-05-12

Changed:

- Public documentation now follows one layout: English first, Russian at the end.
- The current Russian and English public protocol PDFs live in the repository root:
  `UmbrellaX_protocol_public_ru.pdf` and `UmbrellaX_protocol_public_en.pdf`.
- Removed the older short PDF/HTML overview files to avoid two competing public
  document sets.
- Kept public wording focused on the source-available protocol package,
  reproducible local verification, non-commercial security review, and
  responsible disclosure.
- Kept private protocol specifications, working notes, local machine paths,
  unrelated repository plans, and obsolete release-risk wording outside the
  published documentation set.

Security notes:

- Public Access terms remain explicit: this is source-available, not open-source.
- Commercial use, redistribution, embedding in a business product, or operating
  a derived service still requires written permission.
- Current readiness is scoped by `docs/security/current-status.md`; no document
  should imply that unfinished public client paths are open for production use.

### 1.0.0-production - 2026-05-10

Initial clean source package for public protocol inspection and hardening.

Added:

- Public Russian and English protocol PDFs.
- Release manifest, SBOM, and verification artifacts in `docs/security`.
- CI gates for build, documentation, dependency checks, public-access notices,
  and post-quantum backend policy.

Changed:

- Public repository history was collapsed to a clean root commit.
- Public documentation was focused on production materials and verification.
- Internal protocol specifications were kept outside the published repository
  contents.

Security:

- Added a regression for malformed ML-DSA verifier input handling.
- Added a policy script that verifies exact post-quantum backend pins.
- Cleaned unused dependencies from workspace manifests.

---

## Русский

### 3.0.0 — 2026-05-20

Церемония выпуска, консолидирующая post-1.1.0 hardening:

Добавлено:
- Max Ratchet v3 (default-on агрессивный DH + 5-минутный таймер rekey + PQ-расширение каждый 3-й commit + SPQR HMAC отрицаемая аутентификация); см. `docs/audits/max-ratchet-deniability-spec-2026-05-20.md` + `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`
- Крейт `umbrella-discovery` (раунд 7: OPRF-PSI + поиск по `@username` с KT-bind; 38 атакующих тестов D-1..D-8)
- Крейт `umbrella-threshold-identity` (раунд 6: FROST-Ed25519 DKG, PIN-модель Argon2id, обнаружение duress, time-lock восстановление)
- 2 fuzz-цели: `max_ratchet_envelope_{decode,roundtrip}.rs`
- 5 Tamarin-моделей: `aggressive_dh_pcs`, `spqr_deniability`, `discovery`, `sealed_servers_threshold_3of5`, `sealed_servers_threshold_universal`
- Публичный wire-контракт `docs/spec/discovery-integration.md`
- Контракт интеграции с бэкендом `docs/integration/gateway-svc-contract.md`

Изменено:
- Версия пакета workspace: 1.1.0 → 3.0.0 (commit `1ee8dbb3`)
- Закрыт F-CLIENT-FACADE-1 MILESTONE 10/10 (12 sub-sessions; commit `9417096b`)
- PhD-B Pass 5 remediation: закрыто 18 находок (20 коммитов `471e7928..23eda73a`)
- `ClientCore.identity`: `Option<Arc<IdentityKey>>` и `None` на hw bootstrap пути; M-FINAL-1 закрыт через Pass 5 коммит `e7b034ff` (F-CLIENT-HW-1)
- 6 тавтологий в Tamarin-моделях заменены на содержательные multi-rule correspondence lemmas
- Закрыты 3 dudect measurement-artefact находки через bounded-pool паттерн на sub-100 ns сайтах; методология F-DUDECT-HKDF-BORDERLINE-1 задокументирована в `docs/audits/dudect-saturation-methodology-2026-05-19.md`

Безопасность:
- 0 BLOCKER + 0 MAJOR (M-FINAL-1 закрыт) + 1 MINOR-5 carry-over (FFI `with_http_cluster`)
- 14 Tamarin-моделей проверены под `tamarin-prover 1.12.0`; 4 ProVerif-модели (без изменений)
- Базовая линия workspace 2179+ release-mode тестов (пол после раунда 7; пост-1.1.0 серия добавляет ещё)

Проверка: см. `docs/security/release-notes-v3.0.0.md` § Verification.

### Max Ratchet v3 после 1.1.0 — 2026-05-20

Добавлен default-on слой агрессивного DH + 5-минутный таймер rekey +
post-quantum расширение каждый третий commit + SPQR HMAC отрицаемая
аутентификация поверх каждой v3 группы Umbrella.

Реализация в `crates/umbrella-mls/src/max_ratchet/` (модули
`config.rs`, `counter.rs`, `timer.rs`, `spqr.rs`, `group.rs`,
`state.rs`, `envelope.rs`). Wire format — in-band v3 маркер `0xFF`
внутри `ClientPayload::SendMessage.ciphertext`; обратная read-совместимость
с существующими v2 читателями; изменений в proto gateway-svc не требуется.

Покрытие:

- 36 unit-тестов в модулях max_ratchet.
- 10 baseline + 5 active-mode integration-тестов в
  `crates/umbrella-client/tests/facade_max_ratchet_v3.rs`.
- 6 PQ integration-тестов (реальная X-Wing combine интеграция в SPQR
  keying) в `crates/umbrella-mls/tests/test_max_ratchet_pq_real.rs`.
- 5 proptest property-based fuzz-тестов + 5.67M libFuzzer итераций
  в `crates/umbrella-fuzz/fuzz/fuzz_targets/max_ratchet_envelope_*.rs`.
- Criterion benchmarks Apple M2: 27 μs baseline encrypt, 140 μs
  force_rekey, 0.26 μs SPQR HMAC; итог max_ratchet 167.36 μs.
- Tamarin формальные модели для SPQR deniability + aggressive DH PCS
  (Task 5 PhD-B): `crates/umbrella-formal-verification/models/
  spqr_deniability.spthy` + `aggressive_dh_pcs.spthy`.
- Локальная dudect 1M-sample constant-time проверка для `verify_hmac`
  (|t|=0.000 perfect на Apple M2 single-thread; Task 4 PhD-B).
- Forward-secrecy Tamarin лемма в `aggressive_dh_pcs.spthy`.

Спецификация и доказательства:

- `docs/audits/max-ratchet-deniability-spec-2026-05-20.md` — 10/10
  acceptance criteria.
- `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md` —
  таблица per-claim test → measured outcome → numerical bound по
  правилу `feedback_real_not_paperwork`.

Carry-over: внешний крипто-аудит (Cure53 / NCC / Trail of Bits)
остаётся стандартным pre-ship шагом.

### Закрытие F-CLIENT-FACADE-1 MILESTONE 10/10 после 1.1.0 — 2026-05-19

F-CLIENT-FACADE-1 закрыт по 12 под-сессиям (1-10f):

- сессия 1: WebSocket-транспорт + mock gateway + 14 contract-тестов.
- сессия 2: QUIC-транспорт (quinn) + auto-fallback + 17 тестов.
- сессия 3: `send_text` сквозной через `GatewayConnection`.
- сессия 4: `fetch_inbox` через дренаж `IncomingMessage` конвертов.
- сессия 5: реальная MLS group create + add_member.
- сессии 6 / 6c: `cloud_sync_history` 3-of-5 unwrap + Welcome
  distribution + Cloud at-rest dual-write.
- сессия 7: SecretChat sealed-sender wrap/unwrap.
- сессии 8a / 8b / 8c1-3: on-demand KT self-monitor + 3-of-5
  witness-порог + `SignedEpochRoot` production wire codec.
- сессии 9 / 9a-9f: `rotate_identity_full` HW-callback orchestration +
  KT identity rotation wire codec + атомарный swap keystore слотов.
- сессии 10 / 10a-10f: TURN allocation + DTLS / SRTP keying +
  SFrame multi-party media + state-machine transitions +
  webrtc-srtp Context wire-up в facade + `initiate_device_transfer`
  HW-signing+publish orchestration.

Контракт интеграции описан в `docs/integration/gateway-svc-contract.md`.
Публичный FFI-запуск остаётся закрыт до реальной платформенной
проверки, мобильных мостов и серверной интеграции (отдельный milestone).

### Закрытие PhD-B Pass 5 remediation после 1.1.0 — 2026-05-19

Закрыто 18 находок PhD-B Pass 5 за 20 коммитов в `main` между
`471e7928` и `23eda73a`:

- 4 CRITICAL ship-блокера (F-1 Lagrange Шамир / F-2 серверный OPRF /
  F-3 R23 честное naming / F-FFI-2 session-handle паттерн).
- 5 HIGH (F-4 R21 FROST 3-of-5 / F-MLS-1 compile-time gate на
  `UmbrellaXWingProvider` / F-CLIENT-HW-1 + F-IDENT-1 + F-IDENT-2
  hw bootstrap закрывает M-FINAL-1).
- 6 формальных моделей с tautological леммами заменены на substantive
  multi-rule correspondence: `mls_ed25519.spthy`,
  `kt_v1_self_monitoring.spthy`, `kt_v2_self_monitoring.spthy`,
  `sframe_rfc9605.spthy`, `downgrade_resistance.spthy`,
  `type_safe_enforcement.spthy`.
- 3 dudect measurement-artifact находки закрыты bounded-pool
  паттерном на sub-100 ns сайтах; F-DUDECT-HKDF-BORDERLINE-1
  методология задокументирована в
  `docs/audits/dudect-saturation-methodology-2026-05-19.md`.

M-FINAL-1 из независимого review 2026-05-18 поэтому закрыт.
`ClientCore.identity` теперь `Option<Arc<IdentityKey>>`, эфемерный
identity_sk на hw bootstrap пути не материализуется. Сводный отчёт:
`docs/audits/phd-b-pass5-remediation-2026-05-19.md`.

### Слияние раунда 7 «discovery» после 1.1.0 — 2026-05-18

Раунд 7 PhD-B аудит влит:

- Новый крейт `umbrella-discovery` (~5000 LoC) — OPRF-PSI для
  пересечения телефонных номеров и поиска `@username → device_pubkey`,
  оба с KT-bind через `umbrella-kt::verify_inclusion`.
- Порог 3-из-5 через Sealed Servers (реиспользует `umbrella-oprf`
  раунда 2).
- Per-query anonymous-id вывод через HKDF.
- Client-side rate-limit + nonce-replay guard.
- 38 D-series attack-регрессионных под-тестов в 8 файлах.
- Tamarin модель `discovery.spthy` (5 main + 1 exists-trace).
- Спецификация wire-контракта `docs/spec/discovery-integration.md`.

Базовая линия рабочей области 2080 → 2179 release-mode тестов.

### Закрытие PhD-B аудита из шести раундов после 1.1.0 - 2026-05-18

Аудит:

- Влит PR #6 (`84b4d576`): шесть раундов аудита уровня PhD-B по кодовой
  базе 1.1.0.
  - Раунд 1: гибридный постквантовый PhD-аудит (8 находок
    F-PHD-PQ-1..8).
  - Раунд 2: реальная проверка атак (R1-R6 — KyberSlash, MITM, цепочка
    поставок, оффлайн-расшифрование, RNG-инъекция, lldb-zeroize).
  - Раунд 3: закрытие hedged-encaps (паттерн
    Bellare-Hoang-Keelveedhi 2015).
  - Раунд 4: PhD-аудит изъятия устройства (R7-R12; 4 CRITICAL + 3 HIGH).
  - Раунд 5: закрытие изъятия устройства (HW keystore callback +
    миграция `MlockedSecret<T>` + heap-перевод `IdentitySeed`).
  - Раунд 6: архитектурная переделка распределённой идентичности
    (FROST-Ed25519 DKG + PIN-модель + duress + 8 атакующих тестов
    R20-R27).
- Заключение независимого ревьюера: 0 BLOCKER + 1 MAJOR + 3 MINOR.
- 1 MAJOR-находка M-FINAL-1: `ClientCore::new_with_hw_callback` всё
  ещё синтезирует эфемерный `IdentityKey` через `IdentitySeed::generate`
  для обратной совместимости. Seed лежит в heap, zeroize-on-drop, окно
  жизни — микросекунды. Заявление R20 lldb «0 identity_sk hits в 2.2 GB»
  применимо только к round-6 `bootstrap_account`. Удаление вынесено в
  v1.2.x.
- Базовая линия рабочей области теперь 2080 release-mode тестов
  (плюс 103 теста к 1977 базовой линии до раунда 6).

Сводный отчёт: `docs/audits/ROUND-1-TO-7-SUMMARY.md`.

### Гигиена памяти после 1.1.0 - 2026-05-16

Изменено:

- Вывод BIP-39 и SLIP-0010 теперь затирает промежуточную энтропию, PBKDF2 seed,
  HMAC-выход, фиксированные 64-байтовые копии, временные расширенные секреты и
  временные chain code после использования.
- Sealed Sender `OpenedEnvelope.message` теперь возвращает `OpenedMessage` —
  обёртку над расшифрованным текстом, которая затирает память при удалении, а
  не обычный `Vec<u8>`.
- Случайная задержка повторов теперь использует системный генератор (`OsRng`),
  как остальные чувствительные части протокола.

Проверка:

- `bip39_derivation_temporaries_are_zeroizing`
- `slip10_derivation_temporaries_are_zeroized`
- `opened_envelope_message_is_zeroizing_wrapper`
- `retry_jitter_uses_system_rng_not_thread_rng`
- `cargo test -p umbrella-identity -p umbrella-client -p umbrella-sealed-sender --all-features --locked`

### Мониторинг зависимостей после 1.1.0 - 2026-05-15

Добавлено:

- Настройка Dependabot для корневой Cargo-области, отдельного fuzz lockfile и
  GitHub Actions.
- Ежедневный `dependency-monitor` для проверки RustSec по корневому и fuzz
  lockfile, cargo-deny, PQ/backend-границ и сухого отчёта по доступным
  обновлениям.
- Локальный аудит, который не даёт удалить мониторинг или превратить обновления
  зависимостей в тихие изменения `main`.
- Публичный документ по мониторингу зависимостей с правилом: сначала проверка и
  review, потом вливание.

### 1.1.0-security-hardening - 2026-05-15

Добавлено:

- Усиление Key Transparency против split-view: публичные наблюдения эпох,
  проверяемое доказательство раздвоения, строгая история наблюдений и память
  свидетеля, которая не даёт тихо подписать два разных корня одной эпохи.
- Безопасный для приватности публичный формат KT-наблюдения. В нём нет
  account_id, списка устройств, контактов, чатов и текста сообщений.
- Атакующие тесты OPRF по RFC 9497: плохие длины, неверные точки, границы
  размера входа и попытка собрать ответ ниже порога.
- Публичные заметки и манифест выпуска для версии 1.1.0.
- Локальная выпускная заплатка `hpke-rs 0.6.1`, которая убирает
  неиспользуемый optional libcrux-бэкенд HPKE из корневого и fuzz lockfile.

Изменено:

- Общая версия Rust-пакета поднята до 1.1.0.
- Публичная документация теперь честно пишет: локальное обнаружение KT
  split-view реализовано, но живое развёртывание свидетелей и живой обмен
  наблюдениями клиентов остаются границей боевого выпуска.
- В выпускные ворота добавлены проверки KT split-view, локальный аудит
  выпуска, внешний реестр крипто-атак и полный прогон всей рабочей области.

Безопасность:

- Split-view, подписанный злым порогом свидетелей, больше не описывается как
  "закрытый одними подписями". Код теперь даёт сравниваемые наблюдения и
  доказательство, чтобы клиенты могли поймать две разные версии.
- Незавершённые публичные пути по-прежнему закрыто отказывают и не пользуются
  тестовыми конструкторами.
- TLS/SPKI pinning, платформенные проверки, OPRF, backup, sealed sender,
  downgrade, replay, tamper и гонки остаются покрыты локальными тестами и
  честно описанными границами выпуска.
- `RUSTSEC-2026-0124` закрыт в проверяемой цепочке зависимостей: уязвимый
  optional-путь `libcrux-chacha20poly1305 <0.0.8` отсутствует в корневом и fuzz
  lockfile, а не игнорируется.

Проверка:

- `cargo fmt --all -- --check`
- `cargo test --workspace --all-features --locked`
- `bash scripts/audit-protocol-core-attack-gates.sh`
- `bash scripts/audit-local-release-hardening.sh ...`
- `bash scripts/audit-public-access-notices.sh`
- `bash scripts/audit-pq-backend-policy.sh`
- `cargo audit -f crates/umbrella-fuzz/fuzz/Cargo.lock`

### Обновление документации - 2026-05-12

Изменено:

- Публичная документация теперь оформлена единообразно: сначала английский
  текст, в конце русский блок.
- Актуальные публичные PDF протокола лежат в корне репозитория:
  `UmbrellaX_protocol_public_ru.pdf` и `UmbrellaX_protocol_public_en.pdf`.
- Старые короткие PDF/HTML-обзоры удалены, чтобы не было двух конкурирующих
  публичных наборов документов.
- Формулировки оставлены вокруг пакета протокола с доступным для чтения кодом,
  локальной воспроизводимой проверки, некоммерческого анализа безопасности и
  ответственного раскрытия уязвимостей.
- Приватные спецификации протокола, рабочие заметки, локальные пути машины,
  планы других репозиториев и устаревшие формулировки риска выпуска не входят
  в опубликованный набор документации.

Заметки по безопасности:

- Условия Public Access остаются явными: это source-available, не open-source.
- Коммерческое использование, распространение, встраивание в бизнес-продукт или
  запуск производного сервиса требуют письменного разрешения.
- Текущая готовность ограничена файлом `docs/security/current-status.md`;
  незавершённые публичные клиентские пути не должны выглядеть открытыми для
  боевого применения.

### 1.0.0-production - 2026-05-10

Первый чистый исходный пакет для публичной проверки протокола и дальнейшего
усиления.

Добавлено:

- Публичные PDF протокола на русском и английском.
- Манифест выпуска, SBOM и проверочные артефакты в `docs/security`.
- Проверки CI для сборки, документации, зависимостей, публичных пометок доступа
  и постквантовой политики зависимостей.

Изменено:

- Публичная история репозитория сведена к чистому корневому коммиту.
- Публичная документация сфокусирована на production-материалах и проверке.
- Внутренние спецификации протокола не входят в опубликованный репозиторий.

Безопасность:

- Добавлен регрессионный тест для некорректного ML-DSA входа в проверке подписи.
- Добавлен скрипт политики, проверяющий точное закрепление постквантовых
  зависимостей.
- Удалены неиспользуемые зависимости из workspace-манифестов.
