# Public Access Notice

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol is source-available for transparency, cryptographic testing,
non-commercial security testing, reproducible builds, and responsible
vulnerability disclosure. It is not open-source under the Open Source Initiative
definition.

The goal is simple: security researchers can inspect how the production protocol
is built without receiving permission to commercially reuse the implementation.

## Allowed Without a Commercial License

Subject to `LICENSE`, you may:

- read and inspect the source code;
- build and run the code locally;
- run tests, fuzzing, static analysis, formal verification, timing checks, and
  cryptographic interoperability experiments;
- create local, non-distributed modifications needed for security testing,
  cryptographic testing, vulnerability reports, or contributions;
- quote small excerpts in academic papers, advisories, technical posts, or
  vulnerability reports with attribution;
- submit vulnerability reports under `SECURITY.md`;
- submit non-commercial contributions under the CLA process in
  `CONTRIBUTING.md`.

## Not Allowed Without Written Permission

You may not:

- use Umbrella Protocol or modified versions in a commercial product or service;
- embed it into a business application, SDK, hosted service, messenger, wallet,
  infrastructure product, or paid consulting deliverable;
- distribute forks, modified builds, SDKs, or derivative implementations based
  on this repository;
- use Umbrella, UmbrellaX, or Umbrella Protocol marks for another product;
- attack third-party or production infrastructure.

## Public Materials

The public review package contains:

- source code needed to inspect the protocol implementation;
- root-level public protocol PDFs in Russian and English;
- release manifest and SBOM under `docs/security`;
- audit runbooks under `docs/audits`;
- local verification scripts under `scripts`.

Private working notes, local machine paths, unpublished product plans, and
private protocol specifications are intentionally not part of the public package.

## Security Research Safe Harbor

Good-faith security research that follows `SECURITY.md` is permitted by the
repository license. In plain terms: local cryptographic testing, fuzzing,
reverse engineering for vulnerability research, and responsible reporting are
welcome.

This notice is explanatory. The binding terms are in `LICENSE`.

---

## Русский

Umbrella Protocol опубликован как source-available для прозрачности,
криптографического тестирования, некоммерческой проверки безопасности,
воспроизводимых сборок и ответственного раскрытия уязвимостей. Это не
open-source по определению Open Source Initiative.

Цель простая: исследователи безопасности могут проверить, как устроен
production-протокол, но это не даёт права коммерчески использовать реализацию.

## Разрешено без коммерческой лицензии

С учётом `LICENSE` можно:

- читать и изучать исходный код;
- локально собирать и запускать код;
- запускать тесты, fuzzing, статический анализ, формальную проверку,
  тайминговые проверки и криптографические эксперименты совместимости;
- делать локальные нераспространяемые изменения, нужные для проверки
  безопасности, криптотестов, отчётов об уязвимостях или вкладов;
- цитировать небольшие фрагменты в научных работах, advisory, технических
  публикациях или отчётах об уязвимостях с указанием источника;
- отправлять отчёты об уязвимостях по `SECURITY.md`;
- отправлять некоммерческие вклады по процессу CLA из `CONTRIBUTING.md`.

## Нельзя без письменного разрешения

Нельзя:

- использовать Umbrella Protocol или изменённые версии в коммерческом продукте
  или сервисе;
- встраивать его в бизнес-приложение, SDK, hosted service, мессенджер, wallet,
  инфраструктурный продукт или платный консультационный результат;
- распространять форки, изменённые сборки, SDK или производные реализации на
  базе этого репозитория;
- использовать знаки Umbrella, UmbrellaX или Umbrella Protocol для другого
  продукта;
- атаковать стороннюю или production-инфраструктуру.

## Публичные материалы

Публичный пакет для проверки содержит:

- исходный код, нужный для проверки реализации протокола;
- публичные PDF протокола на русском и английском в корне репозитория;
- release manifest и SBOM в `docs/security`;
- runbook-и проверок в `docs/audits`;
- локальные проверочные скрипты в `scripts`.

Приватные рабочие заметки, локальные пути машины, неопубликованные продуктовые
планы и приватные спецификации протокола намеренно не входят в публичный пакет.

## Safe Harbor для исследований безопасности

Добросовестная проверка безопасности по правилам `SECURITY.md` разрешена
лицензией репозитория. Простыми словами: локальное криптографическое
тестирование, fuzzing, reverse engineering для поиска уязвимостей и
ответственные отчёты приветствуются.

Этот документ поясняет правила. Юридически обязательные условия находятся в
`LICENSE`.
