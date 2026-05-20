# Current Status

Дата: 2026-05-19 (PhD-B Pass 5 remediation closure)

[English](#english) | [Русский](#русский)

## Update 2026-05-19 — PhD-B Pass 5 remediation closed

The PhD-B Pass 5 audit findings have been closed across a focused
remediation series (20 closure commits on `main` between
`471e7928` and `23eda73a`). All security and formal-correctness
findings are resolved. Full report:
`docs/audits/phd-b-pass5-remediation-2026-05-19.md`. The single
remaining open item (F-CLIENT-FACADE-1 — chat-facade stubs) is a
Block 7.4 engineering milestone, not a security finding;
integration contract for the closure is documented in
`docs/integration/gateway-svc-contract.md`.

Key transitions from the prior status snapshot below:

- **M-FINAL-1 CLOSED** (commit `e7b034ff`, F-CLIENT-HW-1) —
  `ClientCore::new_with_hw_callback` no longer materialises an
  ephemeral identity_sk in Rust heap. `core.identity` is now
  `Option<Arc<IdentityKey>>` and `None` on the hw bootstrap path;
  the M-FINAL-1 disclosure block is removed entirely. Public-key
  bytes are now sourced from `hw_verifying_key` cache via the new
  `ClientCore::identity_verifying_key()` accessor. The
  v1.2.x removal tracker in the snapshot below is therefore
  satisfied.
- **F-IDENT-1 + F-IDENT-2 CLOSED** (commit `46784d1a`) —
  `HwBackedKeyStore: KeyStore` impl added at
  `crates/umbrella-client/src/keystore/hw_backed.rs`. The new
  keystore has no `seed` field by design; identity-sk operations
  route through `PersistentKeyStoreCallback::sign_identity`.
- **F-MLS-MODEL-1 + 5 MEDIUM formal-model tautologies CLOSED**
  (commits `8d362af6`, `24ec707b`, `6dfc862f`, `977b1974`,
  `c0082bc2`, `23eda73a`) — substantive multi-rule correspondence
  lemmas replace prior tautological proofs across
  `mls_ed25519.spthy`, `kt_v1_self_monitoring.spthy`,
  `kt_v2_self_monitoring.spthy`, `sframe_rfc9605.spthy`,
  `downgrade_resistance.spthy`, `type_safe_enforcement.spthy`. All
  six models now verify under `tamarin-prover` 1.12.0 with
  substantive proof complexity (e.g. `etk_split_brain_prevented`
  in `mls_ed25519.spthy` proven in 172 steps post-closure vs
  ~12 steps pre-closure tautology).
- **F-DUDECT cluster CLOSED** (commit `76947fc0`) — bounded-pool
  pattern applied to sub-100 ns sites (HKDF expand,
  `[u8;32]::ct_eq` baseline, `strip_padding` tail check) at
  `crates/umbrella-tests/tests/dudect_constant_time.rs`. 100 K-
  sample smoke test confirms 47–92 % |t|-reduction across the
  three affected sites.
- **F-CLIENT-FACADE-1 MILESTONE 10/10 CLOSED** (commit `9417096b`,
  session 10f). All 12 sub-sessions on `main`: WebSocket + QUIC
  transports, MLS group create / sealed-sender / KT self-monitor /
  identity rotation / call relay TURN+DTLS+SRTP+SFrame / device
  transfer. Integration contract at
  `docs/integration/gateway-svc-contract.md` is the implemented
  surface, not a future plan. Public FFI bootstrap remains gated
  on external platform attestation, mobile bridges, and real
  server-deployment integration (separate milestone).

The rest of the original status text from 2026-05-18 follows
below. Any contradiction with the update block above resolves in
favour of the update block (newer information).

---

## English

Umbrella Protocol 1.1.0 is a source-available Rust protocol package under
security hardening. It contains real cryptographic crates, test
harnesses, formal models, fuzzing entry points, and local verification scripts.

On 2026-05-18 the PhD-B six-round audit (rounds 1-6) was merged into `main`
via PR #6 (commit `84b4d576`). Round 7 (discovery — PSI + `@username`
lookup with KT bind) merged subsequently, adding the `umbrella-discovery`
crate (~5000 LoC), 38 D-1..D-8 attack-regression sub-tests, the
`discovery.spthy` Tamarin model, and the `docs/spec/discovery-integration.md`
client-side wire contract. The audit chain added the
`umbrella-threshold-identity` crate (FROST-Ed25519 DKG, threshold sign,
PIN/Argon2id KDF, duress detection, lifecycle modules), a `MlockedSecret<T>`
wrapper migrated across seven production storage sites, hedged-encaps in
three production callers (`umbrella-backup`, `umbrella-sealed-sender`,
`umbrella-mls`), iOS Secure Enclave and Android StrongBox real-API bridges,
anti-forensic chat modules (screen-capture overlay + TTL self-destruct),
and eight R20-R27 attack tests with measured numerical outcomes. The
independent reviewer verdict on rounds 1-6
(`docs/audits/phd-b-final-independent-review-2026-05-19.md`) returned
0 BLOCKER + 1 MAJOR (M-FINAL-1, since closed) + 3 MINOR. Workspace baseline
after round 7 is **2179+ release-mode tests** (`cargo test --release
--workspace --all-features`); the post-1.1.0 series on `main`
(F-CLIENT-FACADE-1 10/10 + Pass 5 + Max Ratchet v3 + Tasks 1-5 PhD-B)
adds further tests to that floor.

The MAJOR finding M-FINAL-1 was closed via Pass 5 commit `e7b034ff`
(F-CLIENT-HW-1): `ClientCore.identity` was refactored to
`Option<Arc<IdentityKey>>` and is `None` on the hw bootstrap path; the
ephemeral `IdentitySeed::generate` synthesis was eliminated. The
disclosure block in
`docs/audits/phd-b-distributed-identity-closure-2026-05-19.md` §1.1 records
the pre-closure caveat for historical reference.

The full public client bootstrap is not open for production use yet. Public FFI
bootstrap fails closed until platform verifiers, mobile bridges, and server
integration are wired end to end.

Implemented and currently documented:

- current public release notes:
  `docs/security/release-notes-v1.1.0.md`;
- cryptographic crates for identity, MLS profile, key transparency, OPRF,
  sealed sender, backup, padding, post-quantum helpers, and call primitives;
- internal HTTP/2 production builder with system certificate verification and
  SPKI pinning;
- incomplete `ClientCore::new_with_http2` bootstrap is fail-closed because it
  does not carry SPKI pins for every service and still leaves some transports
  on local stubs;
- server-side attestation gates for backup unwrap and OPRF that fail closed
  without a real platform verifier;
- local platform verifier crate with shared token checks and local WebAuthn
  assertion verification;
- Apple App Attest and Android Play Integrity paths that fail closed until
  external trust material, token parsers, and mobile/server integration are
  connected;
- protocol-core attack gate matrix:
  `docs/security/protocol-core-attack-gates.md`;
- local KT split-view hardening: `umbrella-kt` has public epoch observations,
  verifiable equivocation evidence, strict observation history, witness
  non-equivocation memory, and a public observation encoding that excludes
  account ids, device lists, contacts, and chats;
- local release hardening status:
  `docs/audits/local-release-hardening-status-2026-05-14.md`. It covers local
  formal, fuzz, load, race, KT split-view exchange, secret-leak, and fail-closed
  audits, but it is not a real server or real device proof;
- mandatory server-nonce replay rejection in the production OPRF and backup
  unwrap contexts;
- local dependency release gate runs `cargo deny check` and rejects missing
  `cargo-deny` as a gate failure;
- root and fuzz lockfiles exclude the unused optional `hpke-rs` libcrux HPKE
  backend that pulled `RUSTSEC-2026-0124`; `scripts/audit-pq-backend-policy.sh`
  checks this boundary;
- live dependency monitoring is documented in
  `docs/security/dependency-monitoring.md`; Dependabot prepares dependency PRs,
  and the daily dependency monitor checks root/fuzz RustSec advisories,
  cargo-deny policy, PQ/backend boundaries, and dry-run update drift without
  merging updates into `main`;
- the 2026-05-15 security-hardening audit closed local debug/log leakage in
  sensitive protocol structs, rejected reserved DNS names in production
  transport config, and fixed the blind-postman replay-window growth path where
  unique over-limit messages could consume replay memory;
- the 2026-05-16 memory-hygiene pass zeroizes BIP-39, SLIP-0010, 12-word
  recovery-code and backup unwrap temporaries, adds a zeroizing SQLite row
  plaintext path, returns Sealed Sender plaintext through the zeroizing
  `OpenedMessage` wrapper, and uses the system RNG for retry jitter;
- external crypto attack ledger:
  `docs/security/external-crypto-attack-ledger-2026-05-14.md` and
  `docs/security/external-crypto-attack-ledger-2026-05-15.md`; they record
  external standards/advisories and the local tests or release boundaries that
  answer them;
- formal and local lint gate status recorded in
  `docs/audits/formal-lint-status-2026-05-13.md`.

Not production-ready yet:

- public FFI/client bootstrap;
- Swift, Kotlin, and Web attestation bridges as trust boundaries;
- real server deployment integration;
- real Apple and Android token validation with external trust material;
- real production calling stack: local MLS/SFrame/calls tests are present, but
  real media transport, network behaviour, device audio/video stacks, and
  server relay deployment are still release boundaries;
- public device-certification matrix;
- full production witness deployment for key transparency.
- live KT observation exchange and public witness channels.

The release rule is simple: if a path is not fully wired, it must fail closed or
be documented as a test harness. A test-only path must not look like a
production path.

## Русский

Umbrella Protocol 1.1.0 — набор Rust-крейтов протокола с доступным для чтения
исходным кодом. Сейчас проект проходит усиление безопасности и честное описание
боевых границ. В репозитории есть настоящие криптографические крейты, стенды
проверки, формальные модели, входы для фаззинга и локальные скрипты проверки.

2026-05-18 в `main` влит PR #6 (коммит `84b4d576`) — PhD-B аудит из шести
раундов на кодовой базе 1.1.0. Раунд 7 (discovery — PSI + поиск по
`@username` с KT-bind) влит позднее, добавив крейт `umbrella-discovery`
(~5000 строк), 38 атакующих суб-тестов D-1..D-8, Tamarin-модель
`discovery.spthy` и спецификацию клиентской стороны
`docs/spec/discovery-integration.md`. Аудит добавил крейт
`umbrella-threshold-identity` (FROST-Ed25519 DKG, threshold sign, PIN +
Argon2id KDF, обнаружение duress, lifecycle), обёртку `MlockedSecret<T>` —
смигрировано семь production-мест хранения секретов, hedged-encaps в трёх
production-вызовах (`umbrella-backup`, `umbrella-sealed-sender`,
`umbrella-mls`), мосты к iOS Secure Enclave и Android StrongBox через
настоящий API, анти-форенсик модули чата (overlay при захвате экрана +
TTL self-destruct), и восемь атакующих тестов R20-R27 с измеренными
результатами. Заключение независимого ревьюера по раундам 1-6
(`docs/audits/phd-b-final-independent-review-2026-05-19.md`) — 0 BLOCKER +
1 MAJOR (M-FINAL-1, закрыт позднее) + 3 MINOR. Базовая линия рабочей
области после раунда 7 — **2179+ release-mode тестов** (`cargo test
--release --workspace --all-features`); post-1.1.0 серия в `main`
(F-CLIENT-FACADE-1 10/10 + Pass 5 + Max Ratchet v3 + Tasks 1-5 PhD-B)
добавляет ещё.

MAJOR-находка M-FINAL-1 закрыта в Pass 5 коммитом `e7b034ff`
(F-CLIENT-HW-1): `ClientCore.identity` стал `Option<Arc<IdentityKey>>`
и `None` на hw bootstrap пути; эфемерный синтез `IdentitySeed::generate`
устранён. Раскрытие в
`docs/audits/phd-b-distributed-identity-closure-2026-05-19.md` §1.1
оставлено как исторический снимок до закрытия.

Полный публичный запуск клиента ещё не открыт для боевого применения.
Публичный FFI-запуск закрыто отказывает, пока не связаны платформенные
проверяющие, мобильные мосты и серверная интеграция.

Что уже реализовано и описано:

- публичные заметки текущего выпуска:
  `docs/security/release-notes-v1.1.0.md`;
- криптографические крейты для личности, MLS-профиля, прозрачности ключей,
  OPRF, скрытия отправителя, резервных копий, выравнивания сообщений,
  постквантовых помощников и заготовок звонков;
- внутренний боевой сборщик HTTP/2 с системной проверкой сертификата и
  закреплёнными SPKI-ключами;
- неполный `ClientCore::new_with_http2` закрыто отказывает, потому что он не
  несёт SPKI-ключи для всех сервисов и всё ещё оставляет часть транспортов на
  местных заглушках;
- серверные проверки устройства для развёртки резервного ключа и OPRF, которые
  закрыто отказывают без настоящего платформенного проверяющего;
- локальный крейт платформенной проверки с общими проверками токена и локальной
  проверкой WebAuthn;
- пути Apple App Attest и Android Play Integrity, которые закрыто отказывают,
  пока не подключены внешние корни доверия, разбор токенов и мобильная/серверная
  связка;
- матрица боевых атакующих ворот ядра протокола:
  `docs/security/protocol-core-attack-gates.md`;
- локальное усиление KT против split-view: `umbrella-kt` имеет публичные
  наблюдения эпох, проверяемое доказательство раздвоения, строгую историю
  наблюдений, память свидетеля и публичный формат наблюдения без account_id,
  списка устройств, контактов и чатов;
- статус локальных выпускных ворот:
  `docs/audits/local-release-hardening-status-2026-05-14.md`. Там описаны
  местные формальные проверки, fuzz, нагрузка, гонки, KT split-view сверка,
  аудит утечек секретов и закрытых отказов, но это не доказательство настоящих
  серверов или реальных устройств;
- обязательная защита от повторного использования серверного вызова в боевых
  контекстах OPRF и развёртки резервного ключа;
- локальные ворота зависимостей запускают `cargo deny check`; отсутствие
  `cargo-deny` считается отказом ворот, а не успехом;
- корневой и fuzz lockfile не содержат неиспользуемый optional libcrux-бэкенд
  HPKE из `hpke-rs`, который тянул `RUSTSEC-2026-0124`; это проверяет
  `scripts/audit-pq-backend-policy.sh`;
- живой мониторинг зависимостей описан в
  `docs/security/dependency-monitoring.md`; Dependabot готовит PR с
  обновлениями, а ежедневный сторож проверяет RustSec для корневого и fuzz
  lockfile, cargo-deny, PQ/backend-границы и доступные обновления через dry-run,
  не вливая изменения в `main`;
- аудит усиления от 2026-05-15 закрыл локальные утечки через `Debug`/журналы в
  чувствительных структурах протокола, запретил reserved DNS-имена в боевой
  настройке транспорта и исправил рост replay-памяти blind postman, когда
  уникальные сообщения сверх лимита могли занимать replay-окно;
- проход гигиены памяти от 2026-05-16 затирает временные значения вывода
  BIP-39 и SLIP-0010, возвращает расшифрованный текст Sealed Sender через
  очищаемую обёртку `OpenedMessage` и использует системный генератор для
  случайной задержки повторов;
- внешний реестр криптографических атак:
  `docs/security/external-crypto-attack-ledger-2026-05-14.md` и
  `docs/security/external-crypto-attack-ledger-2026-05-15.md`; они связывают
  внешние стандарты и advisory с локальными тестами или честными границами
  выпуска;
- статус формальных проверок и местных правил в
  `docs/audits/formal-lint-status-2026-05-13.md`.

Что ещё не готово для боя:

- публичный запуск клиента через FFI;
- Swift, Kotlin и Web-мосты как границы доверия;
- связка с настоящим серверным развёртыванием;
- настоящая проверка Apple и Android токенов с внешними корнями доверия;
- настоящий боевой стек звонков: локальные MLS/SFrame/calls тесты есть, но
  настоящий медиа-транспорт, поведение сети, аудио/видео-стек устройств и
  серверное реле всё ещё остаются границами выпуска;
- публичная матрица сертификации устройств;
- полное боевое развёртывание свидетелей прозрачности ключей.
- живой обмен KT-наблюдениями и публичные каналы свидетелей.

Правило выпуска простое: если путь не связан до конца, он должен закрыто
отказывать или быть явно описан как проверочный стенд. Тестовый путь не должен
выглядеть как боевой.
