# Contributing To Umbrella Protocol

[English](#english) | [Русский](#русский)

## English

Thank you for your interest in Umbrella Protocol.

## License Model

Umbrella Protocol is source-available, not open-source. The access model is
explained in [`PUBLIC_ACCESS.md`](PUBLIC_ACCESS.md), and the binding terms are
in [`LICENSE`](LICENSE).

You may read, build, and test the code locally for non-commercial security
testing, cryptographic testing, fuzzing, formal verification, and responsible
vulnerability disclosure. Commercial use and distribution of derivative products
require separate written permission.

## Contributor License Agreement

Before merging a contribution, UmbrellaX LLP requires an Individual CLA or a
Corporate CLA if the contribution is made on behalf of an employer. The CLA
grants UmbrellaX LLP a perpetual, worldwide, non-exclusive license to the
contribution while you retain copyright.

## Pull Request Process

1. Open an issue describing the change before starting substantial work.
2. Use a local branch or platform pull request branch only within the repository
   license terms.
3. Sign the CLA.
4. Sign commits with GPG or Sigstore where possible.
5. Keep public Markdown documentation English first, with the Russian version at
   the end of the same file.
6. Add focused tests for behavior changes.
7. Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

8. Do not include local paths, unrelated repository names, private notes, or
   generated working-plan files in public changes.

## Documentation Standard

Public Markdown files use this layout:

```markdown
# Title

[English](#english) | [Русский](#русский)

## English

...

---

## Русский

...
```

Rust API documentation remains bilingual where the crate requires it. Keep the
meaning identical between languages and avoid operational secrets, private
hosting details, and internal product-roadmap claims.

## Security Contributions

If your contribution relates to a vulnerability, contact
`security@umbrellax.io` first and follow [`SECURITY.md`](SECURITY.md).

## Architecture Changes

Changes to protocol behavior, public APIs, FFI contracts, cryptographic
parameters, or wire formats must be reviewed against the published repository
scope and the private protocol specification before publication.

---

## Русский

Спасибо за интерес к Umbrella Protocol.

## Лицензионная модель

Umbrella Protocol распространяется как source-available, не open-source. Модель
доступа описана в [`PUBLIC_ACCESS.md`](PUBLIC_ACCESS.md), юридически
обязательные условия находятся в [`LICENSE`](LICENSE).

Код можно читать, собирать и локально тестировать для некоммерческой проверки
безопасности, криптотестирования, fuzzing, формальной проверки и ответственного
раскрытия уязвимостей. Commercial use и распространение производных продуктов
требуют отдельного письменного разрешения.

## Contributor License Agreement

Перед включением вклада UmbrellaX LLP требует индивидуальный CLA или
корпоративный CLA, если вклад сделан от имени работодателя. CLA даёт UmbrellaX
LLP бессрочную всемирную неисключительную лицензию на вклад, при этом copyright
остаётся у автора.

## Процесс pull request

1. Перед существенной работой откройте issue с описанием изменения.
2. Используйте локальную ветку или ветку pull request только в рамках лицензии
   репозитория.
3. Подпишите CLA.
4. По возможности подписывайте коммиты через GPG или Sigstore.
5. Публичные Markdown-документы оформляйте так: сначала английский текст, в
   конце русский блок.
6. Добавляйте точечные тесты для изменений поведения.
7. Запустите:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

8. Не добавляйте в публичные изменения локальные пути, названия чужих
   репозиториев, приватные заметки или сгенерированные рабочие планы.

## Стандарт документации

Публичные Markdown-файлы используют такой формат:

```markdown
# Заголовок

[English](#english) | [Русский](#русский)

## English

...

---

## Русский

...
```

Документация Rust API остаётся двуязычной там, где этого требует крейт. Смысл
на двух языках должен совпадать; не добавляйте операционные секреты, приватные
детали хостинга и внутренние продуктовые планы.

## Вклады по безопасности

Если вклад связан с уязвимостью, сначала напишите на `security@umbrellax.io` и
следуйте [`SECURITY.md`](SECURITY.md).

## Архитектурные изменения

Изменения поведения протокола, публичных API, FFI-контрактов,
криптографических параметров или wire-format должны проверяться по публичной
области репозитория и приватной спецификации протокола перед публикацией.
