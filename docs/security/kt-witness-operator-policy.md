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

Umbrella Protocol использует порог 3 из 5 witness для epoch root в Key
Transparency. Это защищает от одного или двух скомпрометированных witness, но
не заставляет локально проверяющий клиент отвергнуть две разные версии root,
если каждая подписана настроенным порогом.

## Production-требование

Пять witness должны управляться независимыми организациями с раздельными:

- административным контролем;
- signing infrastructure;
- cloud или hosting account;
- release process;
- monitoring channel;
- legal-control path там, где это возможно.

Минимум три witness не должны делить ни один из этих видов контроля.

Перед public production реальный deployment manifest должен проходить:

```bash
scripts/audit-kt-witness-deployment.sh docs/security/kt-witness-deployment.csv
```

`docs/security/kt-witness-deployment.example.csv` используется только как
пример схемы; он намеренно содержит example values, которые скрипт отклоняет.

## Обязательный мониторинг

- Каждый witness публикует подписанные наблюдения epoch-root в append-only
  публичный канал.
- Клиенты или monitoring services сравнивают epoch roots для одной epoch.
- Несовпадение для одной epoch считается критическим инцидентом.
- Видимое пользователю сравнение safety-number остаётся последним каналом
  обнаружения, если настроенный порог ведёт себя злоумышленно.

## Что это не гарантирует

Если три настроенных witness намеренно подпишут две разные версии root для
одной epoch, каждый локальный клиент сможет проверить полученную им версию.
Обнаружение тогда требует self-monitoring, public gossip или out-of-band
сравнения safety-number.
