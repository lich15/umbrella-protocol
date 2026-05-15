# Crypto Source Watchlist

Дата: 2026-05-15

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol tracks official cryptographic sources separately from normal
dependency updates. This monitor is report-only: it does not update code
automatically, does not change protocol behavior, and does not merge anything
into `main`.

What is watched:

- X-Wing hybrid KEM on the IETF Datatracker. The current local binding is
  draft revision 10 and the draft-10 known-answer test.
- MLS protocol RFC 9420.
- MLS architecture RFC 9750.
- OPRF RFC 9497.
- SFrame RFC 9605 and the IANA SFrame cipher-suite registry.
- NIST FIPS 203 for ML-KEM.
- NIST FIPS 204 for ML-DSA.
- NIST FIPS 205 for SLH-DSA.

How alerts work:

- `.github/workflows/crypto-source-monitor.yml` runs every six hours.
- `scripts/audit-crypto-source-watchlist.sh --online` fetches the official
  sources and checks the pinned baseline.
- If X-Wing moves from draft 10 to a newer revision, the monitor fails and a
  human review is required.
- If an official RFC/NIST/IANA page changes enough that the expected markers are
  missing, the monitor fails and a human review is required.

Review rule:

- A red monitor does not mean the protocol is broken.
- A red monitor means: stop, read the official change, compare it against local
  code and tests, update the local specification or release boundary, then run
  the full security gate.
- Cryptographic updates are never merged just because a newer version exists.

## Русский

Umbrella Protocol отслеживает официальные криптографические источники отдельно
от обычных обновлений зависимостей. Этот сторож только сообщает: он не обновляет
код автоматически, не меняет поведение протокола и ничего сам не вливает в
`main`.

Что отслеживается:

- X-Wing hybrid KEM в IETF Datatracker. Текущая местная привязка — draft 10 и
  тестовый вектор draft-10.
- MLS protocol RFC 9420.
- MLS architecture RFC 9750.
- OPRF RFC 9497.
- SFrame RFC 9605 и IANA-реестр SFrame cipher suites.
- NIST FIPS 203 для ML-KEM.
- NIST FIPS 204 для ML-DSA.
- NIST FIPS 205 для SLH-DSA.

Как работает сигнал:

- `.github/workflows/crypto-source-monitor.yml` запускается каждые шесть часов.
- `scripts/audit-crypto-source-watchlist.sh --online` читает официальные
  источники и сверяет их с закреплённой базой.
- Если X-Wing перейдёт с draft 10 на новый номер, сторож упадёт и потребует
  ручной разбор.
- Если официальная страница RFC/NIST/IANA изменилась так, что ожидаемые маркеры
  исчезли, сторож упадёт и потребует ручной разбор.

Правило разбора:

- Красный сторож не означает, что протокол уже сломан.
- Красный сторож означает: остановиться, прочитать официальное изменение,
  сравнить его с местным кодом и тестами, обновить местную спецификацию или
  границу выпуска, затем прогнать полные защитные ворота.
- Криптографические изменения никогда не вливаются только потому, что появилась
  более новая версия.
