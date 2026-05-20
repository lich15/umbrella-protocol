# Umbrella Protocol v3.0.0 Release Notes

Date / Дата: 2026-05-20

[English](#english) | [Русский](#русский)

> **Note (2026-05-20 ceremony):** Version 3.0.0 is the release-tag
> ceremony (commit `1ee8dbb3` workspace `version = "3.0.0"`) that
> consolidates the post-v1.1.0 hardening series merged into `main`
> across 88 commits. The interim label «v2.0.0» was skipped; the
> workspace package version bumped directly 1.1.0 → 3.0.0 to reflect
> the substantive scope (F-CLIENT-FACADE-1 milestone closure, PhD-B
> Pass 5 remediation, Round 7 discovery merge, Max Ratchet v3, and
> 6 formal-model tautology closures).
>
> **Замечание (церемония 2026-05-20):** Версия 3.0.0 — церемония
> release-тега (коммит `1ee8dbb3`, `version = "3.0.0"` в workspace),
> которая сводит в один тег пост-v1.1.0 усиление безопасности в
> `main` за 88 коммитов. Промежуточная метка «v2.0.0» пропущена;
> версия пакета бампнута напрямую 1.1.0 → 3.0.0 чтобы отразить
> существенный объём (закрытие F-CLIENT-FACADE-1, Pass 5 remediation,
> вливание Round 7 discovery, Max Ratchet v3 и закрытие 6
> формально-модельных tautology lemmas).

## English

Umbrella Protocol v3.0.0 is the post-v1.1.0 hardening release
consolidating F-CLIENT-FACADE-1 MILESTONE 10/10 closure, PhD-B Pass 5
remediation (18 findings closed), Round 7 private contact discovery
merge (PSI + `@username` with KT bind), Max Ratchet v3 (default-on
aggressive DH + 5-minute timer rekey + post-quantum extension + SPQR
HMAC deniable authentication), and the CI v3.0.0 ceremony cleanup.
The workspace version bumps 1.1.0 → 3.0.0 in commit `1ee8dbb3`.

### Added

- `umbrella-discovery` crate (~5000 LoC; OPRF-PSI + `@username` lookup
  with KT bind; 38 D-1..D-8 attack-regression sub-tests;
  `discovery.spthy` Tamarin model). Merged Round 7 via commit
  `acff5e5b` "Security hardening: PhD-level audits, distributed
  identity, PSI discovery".
- `umbrella-threshold-identity` crate (FROST-Ed25519 DKG 3-of-5;
  PIN/Argon2id model; duress reverse-PIN delete; 24h time-lock
  recovery; HW Keystore callback wired).
- Max Ratchet v3 layer over MLS in `crates/umbrella-mls/src/max_ratchet/`
  (modules: `config.rs`, `counter.rs`, `timer.rs`, `spqr.rs`,
  `group.rs`, `state.rs`, `envelope.rs`). Commits: `5907a9cd`
  (Tasks 1-3 base), `bd17c571` (Task 7 Apple M2 167.36 μs overhead
  benchmark), `078234b5` (Task 4.7 real X-Wing PQ combine wired into
  HMAC keying with 6 integration tests), `2b56ba7a` (Task 6 facade
  + v3 wire codec marker `0xFF` end-to-end), `b1b9968a` (Task 4
  dudect), `7337afc7` (Task 5 Tamarin `aggressive_dh_pcs.spthy`),
  `87db7ad1` (forward-secrecy lemma fix), `11805ba9` (borrowed-mode),
  `41f1cf71` (SpqrAuthFailed error), `62505ba4` (cargo-fuzz targets).
- 5 new Tamarin models: `aggressive_dh_pcs.spthy`,
  `spqr_deniability.spthy`, `discovery.spthy`,
  `sealed_servers_threshold_3of5.spthy`,
  `sealed_servers_threshold_universal.spthy`.
- 2 new fuzz targets in `crates/umbrella-fuzz/fuzz/fuzz_targets/`:
  `max_ratchet_envelope_decode.rs` + `max_ratchet_envelope_roundtrip.rs`
  (workspace total: 29 fuzz targets).
- Public wire-contract specification `docs/spec/discovery-integration.md`.
- Backend integration contract `docs/integration/gateway-svc-contract.md`.

### Changed

- **Workspace version 1.1.0 → 3.0.0** (commit `1ee8dbb3` `chore(release):
  bump workspace version 1.1.0 → 3.0.0`).
- F-CLIENT-FACADE-1 MILESTONE 10/10 closed (commit `9417096b`
  session 10f): 12 sub-sessions (1, 2, 3, 4, 5, 6/6c, 7, 8a/8b/8c1-3,
  9/9a-9f, 10/10a-10f) wired WebSocket + QUIC transports, MLS facades,
  KT self-monitor + 3-of-5 witness threshold, identity rotation,
  calls, and device transfer.
- PhD-B Pass 5 remediation: 18 findings closed across 20 commits
  `471e7928..23eda73a`:
  - 4 CRITICAL: F-1 Shamir 3-of-5 Lagrange, F-2 server-side OPRF,
    F-3 honest R23 naming
    (`decision_logic_r23_5_registry_acceptance_gate`), F-FFI-2
    session-handle pattern.
  - 5 HIGH: F-4 R21 FROST 3-of-5, F-MLS-1 compile-time gate,
    F-CLIENT-HW-1 + F-IDENT-1 + F-IDENT-2 HW bootstrap (closes
    M-FINAL-1 via commit `e7b034ff`; F-IDENT-1+2 via commit
    `46784d1a`).
  - 6 MEDIUM formal-model tautology closures: `mls_ed25519` (commit
    `8d362af6`), `kt_v1_self_monitoring` (`24ec707b`),
    `kt_v2_self_monitoring` (`6dfc862f`), `sframe_rfc9605`
    (`977b1974`), `downgrade_resistance` (`c0082bc2`),
    `type_safe_enforcement` (`23eda73a`). Tautological lemmas were
    replaced with substantive multi-rule correspondence lemmas.
  - 3 dudect measurement-artefact closures via bounded-pool pattern
    at sub-100 ns sites; F-DUDECT-HKDF-BORDERLINE-1 saturation
    methodology decision documented in
    `docs/audits/dudect-saturation-methodology-2026-05-19.md`
    (commit `76947fc0`).
- `ClientCore.identity` is now `Option<Arc<IdentityKey>>` and is
  `None` on the HW bootstrap path; ephemeral `IdentitySeed::generate`
  materialisation is eliminated. M-FINAL-1 (legacy ephemeral seed
  surface) is therefore closed.

### Security

- M-FINAL-1 closed via Pass 5 commit `e7b034ff` (F-CLIENT-HW-1).
- All Pass 5 ship-blockers closed: 0 BLOCKER + 0 MAJOR remaining;
  1 MINOR-5 carry-over (FFI `with_http_cluster`) tracked separately.
- Tamarin: 14 models verified under `tamarin-prover 1.12.0` (was 9
  at v1.1.0). ProVerif: 4 models unchanged. **Total formal models:
  18 (14 .spthy + 4 .pv).**
- 6 formal-model tautology lemmas closed via substantive multi-rule
  correspondence rewrites (see Pass 5 entries above).
- `crates/umbrella-fuzz/fuzz/fuzz_targets/`: 29 fuzz targets
  (was 27 at v1.1.0; +2 Max Ratchet envelope targets).
- 182 `MlockedSecret<T>` usages across the workspace (Round 5
  device-capture closure pattern carried into v3.0.0).
- 12 substantive lemmas in
  `crates/umbrella-formal-verification/models/multi_device_authorization.spthy`
  (corrected count vs earlier «13 lemmas» drift).

### Verification

Reproduce locally:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
bash scripts/audit-protocol-core-attack-gates.sh
bash scripts/audit-local-release-hardening.sh
bash scripts/audit-public-access-notices.sh
bash scripts/audit-pq-backend-policy.sh
bash scripts/audit-dependency-policy.sh target/audit-evidence
bash scripts/verify-tamarin-models.sh
bash scripts/verify-proverif-models.sh
```

Workspace baseline: 2179+ release-mode tests post-Round 7 floor
(post-v1.1.0 series adds further). 24 main-workspace members
(23 `crates/umbrella-*` + `xtask`) + 1 sub-workspace
`crates/umbrella-lints/` (25 total directories in `crates/`).

### Carry-overs to next release

These items remain open and are tracked separately; they are NOT
ship blockers for v3.0.0 (which has 0 BLOCKER + 0 MAJOR):

- External cryptographic review (Cure53 / NCC / Trail of Bits) —
  pre-ship step for a tagged commercial release.
- Real-device runtime tests (iOS Secure Enclave / Android StrongBox) —
  Block 7.10 CI integration carry-over.
- F-PHD-RP-R3-1 SLSA L3 + `cargo-vet` + reproducible-build verification
  gate.
- F-PHD-PQ-5 X-Wing KAT vectors 2..n
  (draft-connolly-cfrg-xwing-kem-10 Appendix C).
- F-PHD-PQ-6 FIPS 203 ACVP test vector set for ML-KEM-768.

### Cross-references

- `docs/audits/ROUND-1-TO-7-SUMMARY.md`
- `docs/audits/phd-b-pass5-remediation-2026-05-19.md`
- `docs/audits/max-ratchet-deniability-spec-2026-05-20.md`
- `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`
- `docs/integration/gateway-svc-contract.md`
- `docs/spec/discovery-integration.md`
- `docs/security/current-status.md`
- `docs/security/production-readiness-boundaries.md`

---

## Русский

Umbrella Protocol v3.0.0 — post-v1.1.0 релиз усиления безопасности,
сводящий закрытие F-CLIENT-FACADE-1 MILESTONE 10/10, PhD-B Pass 5
remediation (18 закрытых findings), вливание Round 7 private contact
discovery (PSI + `@username` с KT bind), Max Ratchet v3 (default-on
aggressive DH + таймер rekey каждые 5 минут + post-quantum extension
+ SPQR HMAC deniable authentication) и CI v3.0.0 ceremony cleanup.
Версия workspace бампнута 1.1.0 → 3.0.0 коммитом `1ee8dbb3`.

### Добавлено

- Крейт `umbrella-discovery` (~5000 LoC; OPRF-PSI + lookup по
  `@username` с KT bind; 38 sub-тестов атак D-1..D-8; Tamarin-модель
  `discovery.spthy`). Влит Round 7 коммитом `acff5e5b` «Security
  hardening: PhD-level audits, distributed identity, PSI discovery».
- Крейт `umbrella-threshold-identity` (FROST-Ed25519 DKG 3-из-5;
  модель PIN/Argon2id; duress reverse-PIN delete; time-lock recovery
  24 ч; HW Keystore callback wired).
- Слой Max Ratchet v3 поверх MLS в `crates/umbrella-mls/src/max_ratchet/`
  (модули: `config.rs`, `counter.rs`, `timer.rs`, `spqr.rs`,
  `group.rs`, `state.rs`, `envelope.rs`). Коммиты: `5907a9cd`
  (Tasks 1-3 база), `bd17c571` (Task 7 бенчмарк Apple M2 167,36 μs
  overhead), `078234b5` (Task 4.7 настоящее X-Wing PQ combine,
  завязанное в HMAC keying, 6 integration-тестов), `2b56ba7a`
  (Task 6 facade + v3 wire codec marker `0xFF` end-to-end),
  `b1b9968a` (Task 4 dudect), `7337afc7` (Task 5 Tamarin
  `aggressive_dh_pcs.spthy`), `87db7ad1` (фикс forward-secrecy
  lemma), `11805ba9` (borrowed-mode), `41f1cf71` (ошибка
  `SpqrAuthFailed`), `62505ba4` (cargo-fuzz цели).
- 5 новых Tamarin-моделей: `aggressive_dh_pcs.spthy`,
  `spqr_deniability.spthy`, `discovery.spthy`,
  `sealed_servers_threshold_3of5.spthy`,
  `sealed_servers_threshold_universal.spthy`.
- 2 новых fuzz-цели в `crates/umbrella-fuzz/fuzz/fuzz_targets/`:
  `max_ratchet_envelope_decode.rs` + `max_ratchet_envelope_roundtrip.rs`
  (всего по workspace: 29 fuzz-целей).
- Публичная спецификация wire-контракта
  `docs/spec/discovery-integration.md`.
- Контракт интеграции с бэкендом
  `docs/integration/gateway-svc-contract.md`.

### Изменено

- **Версия workspace 1.1.0 → 3.0.0** (коммит `1ee8dbb3` `chore(release):
  bump workspace version 1.1.0 → 3.0.0`).
- F-CLIENT-FACADE-1 MILESTONE 10/10 закрыт (коммит `9417096b`
  session 10f): 12 sub-сессий (1, 2, 3, 4, 5, 6/6c, 7, 8a/8b/8c1-3,
  9/9a-9f, 10/10a-10f) wired WebSocket + QUIC транспорты, MLS
  facades, KT self-monitor + порог 3 из 5 свидетелей, ротация
  identity, звонки и device transfer.
- PhD-B Pass 5 remediation: 18 findings закрыты по 20 коммитам
  `471e7928..23eda73a`:
  - 4 CRITICAL: F-1 Shamir 3-из-5 Lagrange, F-2 server-side OPRF,
    F-3 честное имя R23
    (`decision_logic_r23_5_registry_acceptance_gate`), F-FFI-2
    шаблон session-handle.
  - 5 HIGH: F-4 R21 FROST 3-из-5, F-MLS-1 compile-time gate,
    F-CLIENT-HW-1 + F-IDENT-1 + F-IDENT-2 HW bootstrap (закрывает
    M-FINAL-1 коммитом `e7b034ff`; F-IDENT-1+2 коммитом `46784d1a`).
  - 6 MEDIUM формально-модельных tautology закрытий: `mls_ed25519`
    (коммит `8d362af6`), `kt_v1_self_monitoring` (`24ec707b`),
    `kt_v2_self_monitoring` (`6dfc862f`), `sframe_rfc9605`
    (`977b1974`), `downgrade_resistance` (`c0082bc2`),
    `type_safe_enforcement` (`23eda73a`). Tautological lemmas
    заменены на содержательные multi-rule correspondence lemmas.
  - 3 dudect measurement-artefact закрытий через bounded-pool
    pattern на участках < 100 нс; решение по методологии
    F-DUDECT-HKDF-BORDERLINE-1 saturation задокументировано в
    `docs/audits/dudect-saturation-methodology-2026-05-19.md`
    (коммит `76947fc0`).
- `ClientCore.identity` теперь `Option<Arc<IdentityKey>>` и `None`
  на пути HW bootstrap; материализация эфемерного
  `IdentitySeed::generate` устранена. M-FINAL-1 (поверхность
  легасных эфемерных seed) тем самым закрыт.

### Безопасность

- M-FINAL-1 закрыт коммитом Pass 5 `e7b034ff` (F-CLIENT-HW-1).
- Все Pass 5 ship-blockers закрыты: 0 BLOCKER + 0 MAJOR;
  1 MINOR-5 carry-over (FFI `with_http_cluster`) трекается отдельно.
- Tamarin: 14 моделей проверено под `tamarin-prover 1.12.0` (было 9
  в v1.1.0). ProVerif: 4 модели без изменений. **Всего формальных
  моделей: 18 (14 .spthy + 4 .pv).**
- 6 формально-модельных tautology lemmas закрыты содержательными
  multi-rule correspondence переписываниями (см. Pass 5 выше).
- `crates/umbrella-fuzz/fuzz/fuzz_targets/`: 29 fuzz-целей (было 27
  в v1.1.0; +2 целей Max Ratchet envelope).
- 182 использования `MlockedSecret<T>` по workspace (паттерн Round 5
  device-capture закрытия, перенесённый в v3.0.0).
- 12 содержательных lemmas в
  `crates/umbrella-formal-verification/models/multi_device_authorization.spthy`
  (исправленный счёт против раннего drift «13 lemmas»).

### Проверка

Локальный повтор:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
bash scripts/audit-protocol-core-attack-gates.sh
bash scripts/audit-local-release-hardening.sh
bash scripts/audit-public-access-notices.sh
bash scripts/audit-pq-backend-policy.sh
bash scripts/audit-dependency-policy.sh target/audit-evidence
bash scripts/verify-tamarin-models.sh
bash scripts/verify-proverif-models.sh
```

Workspace baseline: 2179+ release-mode тестов на post-Round 7 floor
(post-v1.1.0 серия добавляет ещё). 24 членов основного workspace
(23 `crates/umbrella-*` + `xtask`) + 1 sub-workspace
`crates/umbrella-lints/` (всего 25 директорий в `crates/`).

### Перенесено в следующие выпуски

Эти пункты остаются открытыми и трекаются отдельно; они НЕ являются
ship-блокерами для v3.0.0 (где 0 BLOCKER + 0 MAJOR):

- Внешний криптографический аудит (Cure53 / NCC / Trail of Bits) —
  pre-ship шаг для коммерческого тегированного релиза.
- Тесты на реальных устройствах (iOS Secure Enclave / Android
  StrongBox) — carry-over интеграции Block 7.10 CI.
- F-PHD-RP-R3-1 SLSA L3 + `cargo-vet` + verification gate
  reproducible-build.
- F-PHD-PQ-5 X-Wing KAT векторы 2..n
  (draft-connolly-cfrg-xwing-kem-10 Appendix C).
- F-PHD-PQ-6 набор ACVP test vector FIPS 203 для ML-KEM-768.

### Перекрёстные ссылки

- `docs/audits/ROUND-1-TO-7-SUMMARY.md`
- `docs/audits/phd-b-pass5-remediation-2026-05-19.md`
- `docs/audits/max-ratchet-deniability-spec-2026-05-20.md`
- `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`
- `docs/integration/gateway-svc-contract.md`
- `docs/spec/discovery-integration.md`
- `docs/security/current-status.md`
- `docs/security/production-readiness-boundaries.md`
