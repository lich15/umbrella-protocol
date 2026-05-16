# Changelog

[English](#english) | [Русский](#русский)

## English

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
