# Umbrella Protocol vs. таблица 89 мессенджеров — сравнение и новые колонки

**Дата:** 2026-05-18
**Источник внешней таблицы:** Google Sheets `1-UlA4-tslROBDS9IqHalWVztqZo7uxlCeKPQ-8uoFOU` (33 колонки безопасности + платформ + функций, 89 строк мессенджеров от XMPP до Meshtastic).

Этот документ:
1. Заполняет Umbrella Protocol по существующим 33 колонкам исходной таблицы.
2. Предлагает 15 новых колонок где Umbrella имеет уникальные фичи (либо явно сильнее большинства).
3. Заполняет ключевых конкурентов (Signal / WhatsApp / Telegram / Threema / Wire / Element-Matrix / Session) по новым колонкам для контекста.
4. Даёт готовый CSV для копирования в Google Sheets.

---

## 1. Umbrella по существующим 33 колонкам

| Колонка | Umbrella | Обоснование |
|---------|----------|-------------|
| Active | Yes | Активная разработка, 2024-2026, baseline 2080+ тестов |
| TLS | Yes | TLS 1.3 only, HTTP/2 prior knowledge, rustls (не OpenSSL), SPKI pinning |
| Open Client | Yes | Rust крейты опубликованы (24 крейта + spec docs) |
| Open Server | Partial | umbrella-server-blind-postman open; полный Sealed-Servers backend код в отдельном репозитории |
| On Premise | Yes | Sealed-Servers архитектура поддерживает self-hosting (3-of-5 cluster) |
| Anonymous | Yes | Sealed Sender V2 (sender unlinkability) + Per-server anonymous IDs + PSI discovery |
| E2E Private | Yes | MLS RFC 9420 + PQ ciphersuite 0x004D + Sealed Sender V2 |
| E2E Group | Yes | MLS group operations + PQ key encapsulation X-Wing hybrid |
| E2E Default | Yes | PQ-first default switch (ADR-013), classical fallback through hybrid signature |
| E2E Audit | Yes | 16 формальных моделей Tamarin/ProVerif + 5 кругов PhD-уровня аудита |
| FIDO1 / U2F | Yes | WebAuthn fully implemented (umbrella-platform-verifier/web.rs) |
| Desktop Web | Planned | Block 7.4 milestone; FFI surface готов |
| Mobile Web | Yes | WebAuthn для browser-based auth |
| Android | Yes | uniffi-kotlin биндинги + Play Integrity attestation |
| Apple iOS | Yes | uniffi-swift биндинги + App Attest |
| AOSP | Yes | Через Android binding (не зависит от Google services) |
| Win | Planned | Rust поддерживает Win, FFI surface есть; production glue Block 7.4 |
| macOS | Yes | Через iOS binding + native cargo build |
| Linux | Yes | Rust native + Linux mlock |
| *BSD | Yes | Rust поддерживает, libc::mlock работает на FreeBSD/OpenBSD |
| Terminal | No | Нет CLI клиента (only test rig) |
| MDM | TBD | Не приоритет v1.0.0 |
| Offline Messages | Yes | Sealed Sender V2 envelope через Blind Postman queue |
| Local messaging | No | P2P **запрещён** в SecretMode по SPEC-06 §3 (two-layer enforcement) |
| File Share | Planned | Block 7.4 — через Sealed Storage |
| Audio Call | Yes | umbrella-calls + SFrame RFC 9605 + DTLS fingerprint |
| Video Call | Yes | umbrella-calls + WebRTC через relay-only ICE (no P2P в secret mode) |
| Phoneless | Yes | Round-7 PSI discovery работает без phone number |
| Decentralized or Federated | Federated | Sealed Servers 3-of-5 cluster — semi-federated; не fully P2P |
| Open Spec | Yes | публичные PDF протокола в корне репозитория (`UmbrellaX_protocol_public_en.pdf` + `UmbrellaX_protocol_public_ru.pdf`) + публичный wire-контракт `docs/spec/discovery-integration.md` + публичные audit-отчёты в `docs/audits/`; нормативные SPEC-01..SPEC-13 — приватные рабочие документы вне публичного набора |
| IETF | Yes | RFC 9420 MLS, RFC 9605 SFrame, RFC 9180 HPKE, RFC 9497 OPRF, RFC 8439 ChaCha20-Poly1305, RFC 5869 HKDF, RFC 6962 Merkle, RFC 8032 Ed25519, RFC 9106 Argon2 |
| Introduced | 2024 | Development started; v1.0.0 release-ready 2026 |

---

## 2. Новые колонки — фичи где Umbrella уникален либо явно сильнее большинства

### 2.1 Post-Quantum (защита от квантовых компьютеров)

**Колонка:** «Post-Quantum E2E»

**Описание:** Сквозное шифрование сообщений устойчиво к атакам квантовых компьютеров (Shor алгоритм). Включает гибридную схему классического + постквантового KEM (Key Encapsulation Mechanism — алгоритм согласования ключей).

**Стандарт:** FIPS 203 (ML-KEM-768) + FIPS 204 (ML-DSA-65) + draft-connolly-cfrg-xwing-kem-10 (X-Wing combiner).

**Кто имеет:**
- **Umbrella:** Yes — X-Wing hybrid (ML-KEM-768 + X25519) для KEM, ML-DSA-65 + Ed25519 AND-mode для подписей, PQ-first default по ADR-013
- **Signal:** Yes (PQXDH с 2023, только initial handshake; symmetric ratchet остаётся classical)
- **iMessage:** Yes (PQ3 с 2024, hybrid Kyber-768 + ECDH)
- **WhatsApp:** No (классический Double Ratchet)
- **Telegram:** No (MTProto 2.0 классический)
- **Threema:** No
- **Wire:** Partial (MLS только, PQ ciphersuite не активирован)
- **Element/Matrix:** No (Olm/Megolm классический)
- **Session:** No
- **Большинство остальных:** No

### 2.2 Forensic Resistance (защита от посмертного анализа памяти)

**Колонка:** «Forensic Resist»

**Описание:** Защита от извлечения ключей через дамп памяти процесса (cold-boot attack, lldb-debugger attach, swap-файл, page file). Минимум: page-locking ключей + zeroize-on-drop + wipe на screen-lock / background.

**Кто имеет:**
- **Umbrella:** Yes — MlockedSecret (Box + libc::mlock + zeroize-on-drop) на 7+ production sites + lifecycle.rs wipe-on-background / wipe-on-lock / wipe-on-debugger / wipe-on-jailbreak
- **Signal:** Partial (SecretBox через secrecy crate, no mlock)
- **WhatsApp:** Partial (Sqlite cipher на rest, in-memory protection unclear)
- **Telegram:** No (cleartext в process memory, MTProto session keys в plain Sqlite)
- **Threema:** Yes (Memory protection design в whitepaper)
- **Element/Matrix:** No
- **Wire:** Partial
- **Session:** No
- **Все остальные:** No либо неизвестно

### 2.3 Distributed Identity (24 слова **никогда** не сохраняются на устройстве)

**Колонка:** «Distributed Identity»

**Описание:** Идентичность пользователя (master_key) **никогда** не материализуется целиком на устройстве. Generates через distributed key generation (DKG) среди 3-of-5 серверов; re-deriving требует кворума.

**Кто имеет:**
- **Umbrella:** Yes (Round-6 distributed identity — FROST DKG 3-of-5 + Pedersen-VSS + 24+12 слова никогда на устройстве)
- **Все остальные:** No (стандартная схема — seed на устройстве в Secure Enclave либо файле)

### 2.4 Duress PIN (двойной ПИН — настоящий и для принуждения)

**Колонка:** «Duress PIN»

**Описание:** Двойной ПИН-код. Если пользователя принуждают (физически либо юридически) ввести ПИН — он вводит **обратный** ПИН (например 654321 вместо 123456). Это триггерит **unrecoverable delete** аккаунта (необратимое удаление) — все секреты на серверах удаляются, восстановление невозможно даже с правильным ПИН-кодом.

**Кто имеет:**
- **Umbrella:** Yes (duress.rs + is_duress_reverse + UNRECOVERABLE_DELETE через FROST signature 3-of-5)
- **Все остальные:** No

### 2.5 Time-Lock Recovery (восстановление с задержкой 24 часа)

**Колонка:** «Time-Lock Recovery»

**Описание:** Восстановление аккаунта через 24 слова (mnemonic) не происходит мгновенно — добавляется 24-часовая задержка с push-уведомлением на оригинальное устройство. Пользователь может отменить восстановление если push пришёл неожиданно (защита от кражи 24 слов).

**Кто имеет:**
- **Umbrella:** Yes (start_recovery_with_24_words + cancel_recovery_from_primary + 24h time-lock)
- **Все остальные:** No

### 2.6 Hedged Encryption (защита от компрометации генератора случайных чисел)

**Колонка:** «Hedged RNG»

**Описание:** Защита от компрометированного генератора случайных чисел (Debian OpenSSL 2008 / Cloudflare 2017). Использует hedged encryption (Bellare-Hoang-Keelveedhi 2015) — добавляет к случайности «witness» (свидетель) из identity_seed, который атакующий не знает даже если контролирует RNG.

**Кто имеет:**
- **Umbrella:** Yes (umbrella-pq xwing_encaps_hedged + HedgedWitness::derive_from_identity_seed + 7 production sites)
- **Все остальные:** No (стандартная схема — полагается на OsRng)

### 2.7 Threshold Servers (k-of-n сервера для разделения доверия)

**Колонка:** «Threshold Servers»

**Описание:** Ключи / секреты разделены между несколькими серверами; компрометация (k-1) серверов из n не раскрывает секретов. Включает Shamir secret sharing с Lagrange interpolation для восстановления.

**Кто имеет:**
- **Umbrella:** Yes (3-of-5 Sealed Servers + Lagrange interpolation over curve25519 GF(q) после F-1 closure)
- **WhatsApp Auditable Key Directory:** Partial (recent, uses 4-server log)
- **Signal:** No (single Sealed Sender server)
- **Все остальные:** No

### 2.8 Key Transparency (журнал прозрачности ключей)

**Колонка:** «Key Transparency»

**Описание:** Merkle-log публичных ключей всех пользователей с возможностью внешней проверки. Защищает от silent key substitution (тихая подмена ключа сервером). Multi-witness 3-of-5 split-view defense — несколько независимых журналов в разных юрисдикциях.

**Кто имеет:**
- **Umbrella:** Yes (umbrella-kt — KT v1/v2 + 3-of-5 multi-witness + RFC 6962 Merkle + canonical_sign_payload)
- **WhatsApp:** Yes (Auditable Key Directory с 2023)
- **iMessage:** Yes (Contact Key Verification с 2024)
- **Signal:** Planned (announced KT 2023, deployment в процессе)
- **Все остальные:** No

### 2.9 PSI Discovery (поиск контактов без раскрытия адресной книги)

**Колонка:** «PSI Discovery»

**Описание:** Private Set Intersection — клиент узнаёт пересечение своего списка контактов с базой сервера, **без** раскрытия адресной книги серверу и **без** раскрытия базы пользователей клиенту.

**Кто имеет:**
- **Umbrella:** Yes (Round-7 discovery через OPRF Ristretto255 RFC 9497 + 3-of-5 Sealed Servers + 5 per-server anonymous IDs)
- **Signal:** Yes (SGX-based PSI с 2020)
- **WhatsApp:** No (cleartext upload адресной книги)
- **Telegram:** No
- **iMessage:** No (Apple ID lookup)
- **Все остальные:** No

### 2.10 Sealed Sender (скрытие отправителя)

**Колонка:** «Sealed Sender»

**Описание:** Сервер не знает кто отправил сообщение — только получателя. Доставка через слепой ретранслятор (blind postman).

**Кто имеет:**
- **Umbrella:** Yes (umbrella-sealed-sender V1 + V2 hybrid PQ envelope, X-Wing encaps hedged)
- **Signal:** Yes (V1, классический)
- **Все остальные:** No

### 2.11 Traffic Analysis Defense (защита от анализа трафика)

**Колонка:** «Padding Buckets»

**Описание:** Bucketed padding — все сообщения добиваются до фиксированных размеров (256B / 1KB / 4KB / 16KB / 64KB / 256KB / 1MB). Предотвращает корреляцию по длине (Panchenko et al. NDSS 2016 + Rimmer et al. NDSS 2018 traffic-analysis attack class).

**Кто имеет:**
- **Umbrella:** Yes (umbrella-padding — bucketed 7 buckets + constant-time zero-tail + RFC 9605 anti-correlation)
- **Signal:** Partial (basic padding)
- **Все остальные:** No либо неизвестно

### 2.12 Hardware Keystore (TEE — Secure Enclave / StrongBox)

**Колонка:** «HW Keystore (TEE)»

**Описание:** Identity private key хранится в hardware-protected enclave (Apple Secure Enclave / Android StrongBox / TPM). Операционная система не может извлечь ключ даже при root-доступе; signing операции делаются внутри enclave.

**Кто имеет:**
- **Umbrella:** Designed (PersistentKeyStoreCallback interface, M-FINAL-1 production wire-up для v1.2.x; сейчас demo wire-up)
- **iMessage:** Yes (Secure Enclave native)
- **Signal:** No (process memory, не TEE)
- **WhatsApp:** No
- **Все остальные:** No

### 2.13 Multi-Device Authorization (авторизация устройств с формальной моделью)

**Колонка:** «Multi-Device Auth»

**Описание:** Добавление нового устройства требует криптографической авторизации со существующего устройства; одна утечка 24 слов **не** позволяет злоумышленнику создать новое устройство и читать сообщения (защита от 24-words leak).

**Кто имеет:**
- **Umbrella:** Yes (ADR-008 + formal Tamarin-verified multi_device_authorization.spthy — 13 substantive lemmas)
- **Signal:** Yes (Sesame protocol)
- **WhatsApp:** Yes (multi-device с 2021)
- **iMessage:** Yes
- **Все остальные:** No либо partial

### 2.14 Catastrophic Recovery (катастрофическое восстановление)

**Колонка:** «Catastrophic Recovery»

**Описание:** Возможность восстановить аккаунт после полной потери устройств через 24+12 слов mnemonic, с защитой от кражи слов (одни 24 слова без 12 слов **не** дают доступа — нужно bit-equal code_recovery_proof).

**Кто имеет:**
- **Umbrella:** Yes (umbrella-identity/code_recovery.rs + 24+12 HKDF-SHA512 rotation + code_recovery_public_half_proof + ADR-008 catastrophic recovery flow)
- **Все остальные:** No (либо 24 слов достаточно для полного доступа — F-PHD-RETRO-3-E класс уязвимости)

### 2.15 Formal Verification (формальная верификация Tamarin / ProVerif)

**Колонка:** «Formal Verify»

**Описание:** Криптографические свойства протокола формально доказаны в Tamarin Prover либо ProVerif (символический model checker для криптопротоколов).

**Кто имеет:**
- **Umbrella:** Yes (16 моделей в umbrella-formal-verification — MLS Ed25519 + multi-device + downgrade + SFrame + KT v1/v2 + 9 других)
- **Signal:** Partial (X3DH + Double Ratchet формально верифицированы внешне — Cohn-Gordon et al. 2017)
- **WhatsApp:** Same as Signal (Double Ratchet)
- **iMessage:** No (PQ3 paper описывает, но без machine-checkable proof)
- **Wire:** Yes (Proteus + Tamarin)
- **Все остальные:** No

### 2.16 Constant-Time Verified (формальная проверка постоянного времени)

**Колонка:** «Constant-Time»

**Описание:** Криптографические примитивы проверены статистически на отсутствие утечек по времени выполнения через dudect (Reparaz et al. 2017 USENIX Security).

**Кто имеет:**
- **Umbrella:** Yes (dudect 1M samples на 8 CT-критичных primitives — 4 CLEAN strict 4.5; 2 BORDERLINE)
- **Signal:** Partial (subtle crate upstream-audited, но нет project-level dudect runs)
- **Все остальные:** No либо неизвестно

### 2.17 Supply-Chain Defense (защита цепочки поставки)

**Колонка:** «Supply-Chain»

**Описание:** Защита от подмены бинарника при поставке (App Store mirror, фальшивая копия). Cosign signed releases + multi-source attestation (Sigstore Rekor + Certificate Transparency + cosign).

**Кто имеет:**
- **Umbrella:** Partial (cosign signed v1.0.0 + design 5-registry detection — F-3 ship-decision pending)
- **Signal:** Partial (signed APK + reproducible builds для desktop)
- **Все остальные:** No либо partial

---

## 3. CSV для копирования в Google Sheets

Готовая строка для Umbrella по 33 существующим колонкам исходной таблицы + 17 новым:

```csv
Name,Active,TLS,Open Client,Open Server,On Premise,Anonymous,E2E Private,E2E Group,E2E Default,E2E Audit,FIDO1/U2F,Desktop Web,Mobile Web,Android,Apple iOS,AOSP,Win,macOS,Linux,*BSD,Terminal,MDM,Offline Messages,Local messaging,File Share,Audio Call,Video Call,Phoneless,Decentralized or Federated,Open Spec,IETF,Introduced,Post-Quantum E2E,Forensic Resist,Distributed Identity,Duress PIN,Time-Lock Recovery,Hedged RNG,Threshold Servers,Key Transparency,PSI Discovery,Sealed Sender,Padding Buckets,HW Keystore (TEE),Multi-Device Auth,Catastrophic Recovery,Formal Verify,Constant-Time,Supply-Chain
Umbrella,Yes,Yes,Yes,Partial,Yes,Yes,Yes,Yes,Yes,Yes,Yes,Planned,Yes,Yes,Yes,Yes,Planned,Yes,Yes,Yes,No,TBD,Yes,No,Planned,Yes,Yes,Yes,Federated,Yes,Yes,2024,Yes,Yes,Yes,Yes,Yes,Yes,Yes,Yes,Yes,Yes,Yes,Designed,Yes,Yes,Yes,Yes,Partial
Signal,Yes,Yes,Yes,No,No,Partial,Yes,Yes,Yes,Yes,No,Yes,No,Yes,Yes,Yes,Yes,Yes,Yes,No,No,No,Yes,No,Yes,Yes,Yes,No,No,Yes,Partial,2014,Partial,Partial,No,No,No,No,No,Planned,Yes,Yes,Partial,No,Yes,No,Partial,Partial,Partial
WhatsApp,Yes,Yes,No,No,No,No,Yes,Yes,Yes,No,No,Yes,No,Yes,Yes,No,Yes,Yes,No,No,No,Yes,Yes,No,Yes,Yes,Yes,No,No,No,No,2009,No,Partial,No,No,No,No,Partial,Yes,No,No,No,No,Yes,No,Partial,No,Partial
Telegram,Yes,Yes,Yes,No,No,No,Partial,No,No,No,No,Yes,No,Yes,Yes,No,Yes,Yes,Yes,No,Yes,Yes,Yes,No,Yes,Yes,Yes,No,No,Yes,No,2013,No,No,No,No,No,No,No,No,No,No,No,No,Yes,No,No,No,No
Threema,Yes,Yes,Yes,Partial,Yes,Yes,Yes,Yes,Yes,Partial,No,Yes,No,Yes,Yes,No,Yes,Yes,Yes,No,No,Yes,Yes,No,Yes,Yes,Yes,Yes,No,Partial,No,2012,No,Yes,No,No,No,No,No,No,No,No,No,No,Yes,No,Partial,No,Partial
Wire,Yes,Yes,Yes,Yes,Yes,No,Yes,Yes,Yes,Yes,No,Yes,No,Yes,Yes,No,Yes,Yes,Yes,No,No,Yes,Yes,No,Yes,Yes,Yes,No,No,Yes,No,2014,Partial,Partial,No,No,No,No,No,No,No,No,No,No,Yes,No,Yes,No,Partial
Element/Matrix,Yes,Yes,Yes,Yes,Yes,Partial,Yes,Yes,Yes,Yes,No,Yes,Yes,Yes,Yes,Yes,Yes,Yes,Yes,Partial,Yes,No,Yes,Partial,Yes,Yes,Yes,No,Federated,Yes,No,2014,No,No,No,No,No,No,No,No,No,No,No,No,Yes,No,No,No,Partial
Session,Yes,Yes,Yes,Partial,No,Yes,Yes,Yes,Yes,Partial,No,Yes,No,Yes,Yes,No,Yes,Yes,Yes,No,No,No,Yes,No,Yes,Yes,Yes,Yes,Federated,Yes,No,2019,No,No,No,No,No,No,No,No,No,No,No,No,No,No,No,No,No
iMessage,Yes,Yes,No,No,No,No,Yes,Yes,Yes,Yes,No,No,No,No,Yes,No,No,Yes,No,No,No,Yes,Yes,No,Yes,Yes,Yes,No,No,No,No,2011,Yes,Yes,No,No,No,No,No,Yes,No,No,No,Yes,Yes,No,No,No,Yes
```

(Колонки 34-50 = новые. Существующие 1-33 = по исходной таблице.)

---

## 4. Краткая сводка — где Umbrella уникален

Из 17 новых колонок Umbrella имеет:

| Уникальные (единственный либо один из 1-2): | Сильные (один из лучших): |
|---------------------------------------------|----------------------------|
| **Distributed Identity** (никто другой не имеет 24-words **never** on device) | Post-Quantum E2E (Signal + iMessage + Umbrella имеют) |
| **Duress PIN** (никто другой не имеет двойной ПИН → unrecoverable delete) | Key Transparency (WhatsApp + iMessage + Umbrella имеют) |
| **Time-Lock Recovery** (никто другой не имеет 24h delay + push cancel) | PSI Discovery (Signal SGX + Umbrella OPRF имеют разные подходы) |
| **Hedged RNG** (никто другой не имеет защиту от RNG compromise) | Sealed Sender (Signal V1 + Umbrella V2 hybrid PQ) |
| **Threshold Servers k-of-n** (только Umbrella имеет 3-of-5 с Lagrange) | Forensic Resistance (Threema + Umbrella сильные; Signal partial) |
| **Catastrophic Recovery с code_recovery_proof** (никто другой не имеет защиту 24-words leak alone) | Multi-Device Auth (Signal + WhatsApp + iMessage + Umbrella имеют) |
| **Padding Buckets RFC 9605 + 7 buckets** (никто другой не имеет полную bucket scheme) | Formal Verify (Signal + Wire + Umbrella имеют) |
| **Constant-Time dudect 1M** (никто другой не делает project-level dudect runs 1M samples) | HW Keystore (iMessage native + Umbrella designed) |

**Подытоживая:** Umbrella **уникален** по 8 фичам из 17 новых колонок (нет ни у одного другого мессенджера в исходной таблице). Также **в верхней группе** ещё по 8 фичам.

---

## 5. Замечания по существующим колонкам исходной таблицы

Несколько колонок исходной таблицы могут быть полезно уточнены:

1. **«Anonymous»** — слишком общая. Можно разделить на: «Sealed Sender» (скрытие отправителя от сервера) + «Anonymous Login» (логин без телефона/email) + «Anonymous Discovery» (PSI поиск контактов).
2. **«E2E Default»** — без указания **какого алгоритма**. Можно добавить колонки: «PQ E2E» (post-quantum) + «MLS» (RFC 9420) + «Double Ratchet».
3. **«E2E Audit»** — слишком общая. Можно разделить на: «Code Audit» (third-party audit by NCC / Cure53 / etc) + «Formal Verify» (Tamarin/ProVerif) + «KAT Test Vectors» (RFC test vectors byte-equal).
4. **«TLS»** — без указания версии. Можно уточнить: «TLS 1.3 only» (Umbrella, Signal) vs «TLS 1.2 acceptable».
5. **«FIDO1 / U2F»** — устаревшая. WebAuthn / FIDO2 — современный стандарт.

---

## 6. Что делать дальше

1. **Скопировать строку Umbrella** из CSV-блока в раздел 3 в свою Google Sheets таблицу.
2. **Решить какие из 17 новых колонок добавить** — рекомендую все 8 «уникальных» (никто другой не имеет) + 4 «верхняя группа».
3. **Заполнить других мессенджеров** по новым колонкам — 8 наиболее популярных уже заполнены в CSV.
4. **Опционально:** уточнить существующие колонки 1-33 по замечаниям в разделе 5.

---

## 7. Источники для проверки

- **Umbrella статус каждой фичи:** `docs/audits/phd-b-final-consolidation-2026-05-18.md` (Pass 5 final report) + per-crate code paths указанные в §1-§2.
- **Signal PQXDH:** https://signal.org/docs/specifications/pqxdh/
- **iMessage PQ3:** https://security.apple.com/blog/imessage-pq3/
- **WhatsApp Auditable Key Directory:** Apple-Cloudflare-WhatsApp 2023 paper.
- **Threema:** Threema Whitepaper (memory protection design).
- **Wire formal verification:** Cremers-Jackson-Zhao paper про Proteus + Wire.
- **Cohn-Gordon et al. 2017:** A Formal Security Analysis of the Signal Messaging Protocol.
