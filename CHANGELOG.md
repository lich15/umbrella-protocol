# Changelog

[English](#english) | [Русский](#русский)

## English

### Documentation refresh - 2026-05-12

Changed:

- Public documentation now follows one layout: English first, Russian at the end.
- The current Russian and English public protocol PDFs live in the repository root:
  `UmbrellaX_protocol_public_ru.pdf` and `UmbrellaX_protocol_public_en.pdf`.
- Removed the older short PDF/HTML overview files to avoid two competing public
  document sets.
- Kept public wording focused on the production package, reproducible local
  verification, non-commercial security review, and responsible disclosure.
- Kept private protocol specifications, working notes, local machine paths,
  unrelated repository plans, and obsolete release-risk wording outside the
  published documentation set.

Security notes:

- Public Access terms remain explicit: this is source-available, not open-source.
- Commercial use, redistribution, embedding in a business product, or operating
  a derived service still requires written permission.
- Production-ready means complete for the published production scope; it does
  not mean risk-free or immune to future vulnerabilities.

### 1.0.0-production - 2026-05-10

Initial clean production-ready source package.

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

### Обновление документации - 2026-05-12

Изменено:

- Публичная документация теперь оформлена единообразно: сначала английский
  текст, в конце русский блок.
- Актуальные публичные PDF протокола лежат в корне репозитория:
  `UmbrellaX_protocol_public_ru.pdf` и `UmbrellaX_protocol_public_en.pdf`.
- Старые короткие PDF/HTML-обзоры удалены, чтобы не было двух конкурирующих
  публичных наборов документов.
- Формулировки оставлены вокруг production-пакета, локальной воспроизводимой
  проверки, некоммерческого security-review и ответственного раскрытия
  уязвимостей.
- Приватные спецификации протокола, рабочие заметки, локальные пути машины,
  планы других репозиториев и устаревшие формулировки риска выпуска не входят
  в опубликованный набор документации.

Заметки по безопасности:

- Условия Public Access остаются явными: это source-available, не open-source.
- Коммерческое использование, распространение, встраивание в бизнес-продукт или
  запуск производного сервиса требуют письменного разрешения.
- Production-ready означает завершённость в опубликованной области, но не
  обещает нулевой риск или невозможность будущих уязвимостей.

### 1.0.0-production - 2026-05-10

Первый чистый production-ready исходный пакет.

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
