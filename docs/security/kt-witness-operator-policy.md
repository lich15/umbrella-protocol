# Key-Transparency Witness Operator Policy

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol accepts a 3-of-5 witness threshold for key-transparency epoch
roots. This protects against one or two compromised witnesses, but it cannot
make a locally verified client reject two different roots that were each signed
by the configured threshold.

## Production Requirement

The five witnesses must be operated by independent organizations with separate:

- administrative control;
- signing infrastructure;
- cloud or hosting account;
- release process;
- monitoring channel;
- legal-control path where feasible.

At least three witnesses must not share any one of those controls.

Before public production, the real deployment manifest must pass:

```bash
scripts/audit-kt-witness-deployment.sh docs/security/kt-witness-deployment.csv
```

Use `docs/security/kt-witness-deployment.example.csv` only as a schema example;
it intentionally contains example values that the script rejects.

## Required Monitoring

- Each witness publishes signed epoch-root observations to an append-only public
  channel.
- Every witness must keep local memory of `log + epoch -> root + size`.
  Repeating the same head is allowed, but a second different root for the same
  epoch must be rejected as an equivocation attempt.
- Public observations contain only technical epoch heads: log_id, previous
  root, current root, size, timestamp, and signatures. They do not contain
  phone number, account_id, device list, contacts, or chats.
- Clients or monitoring services compare epoch roots for the same epoch.
- A mismatch for the same epoch is treated as a critical incident.
- User-visible safety-number comparison remains the last-resort detection
  channel when the configured threshold is malicious.

## Non-Guarantee

If three configured witnesses intentionally sign two different roots for the
same epoch, each local client can verify the view it received. Detection then
requires self-monitoring, public gossip, or out-of-band safety-number
comparison.

---

## Русский

Umbrella Protocol использует порог 3 из 5 свидетелей для корня эпохи в журнале
ключей. Это защищает от одного или двух захваченных свидетелей, но не
заставляет локально проверяющий клиент отвергнуть две разные версии корня, если
каждая версия подписана настроенным порогом.

## Требование для боевого развёртывания

Пять свидетелей должны управляться независимыми организациями с раздельными:

- административным контролем;
- узлом подписи;
- облачной или серверной учётной записью;
- порядком выпуска изменений;
- каналом наблюдения;
- юридическим управлением там, где это возможно.

Минимум три свидетеля не должны делить ни один из этих видов контроля.

Перед боевым публичным развёртыванием настоящий манифест развёртывания должен
проходить:

```bash
scripts/audit-kt-witness-deployment.sh docs/security/kt-witness-deployment.csv
```

`docs/security/kt-witness-deployment.example.csv` используется только как
пример схемы; он намеренно содержит примерные значения, которые скрипт
отклоняет.

## Обязательный мониторинг

- Каждый свидетель публикует подписанные наблюдения корня эпохи в публичный
  канал, где старые записи нельзя незаметно переписать.
- Каждый свидетель обязан хранить локальную память `журнал + эпоха -> root + размер`.
  Повтор той же головы разрешён, но второй другой root для той же эпохи должен
  отвергаться как попытка раздвоения.
- Публичные наблюдения содержат только технические головы эпох: log_id,
  предыдущий root, текущий root, размер, время и подписи. Они не содержат
  телефон, account_id, список устройств, контакты или чаты.
- Клиенты или службы наблюдения сравнивают корни для одной эпохи.
- Несовпадение для одной эпохи считается критическим инцидентом.
- Видимое пользователю сравнение номера безопасности остаётся последним
  каналом обнаружения, если настроенный порог ведёт себя злоумышленно.

## Что это не гарантирует

Если три настроенных свидетеля намеренно подпишут две разные версии корня для
одной эпохи, каждый локальный клиент сможет проверить полученную им версию.
Обнаружение тогда требует самопроверки, публичной сверки наблюдений или
сравнения номера безопасности вне приложения.
