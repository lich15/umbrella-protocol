# Dependency Monitoring

Дата: 2026-05-15

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol uses live dependency monitoring, but dependency updates are
not merged into `main` automatically.

What runs:

- Dependabot checks the root Rust workspace every day.
- Dependabot checks the separate fuzz `Cargo.lock` every day.
- Dependabot checks GitHub Actions weekly.
- `.github/workflows/dependency-monitor.yml` runs every six hours and on relevant
  pull requests.
- The monitor runs `cargo audit` for the root lockfile and for
  `crates/umbrella-fuzz/fuzz/Cargo.lock`.
- The monitor runs the local PQ/backend policy gate, including the check that
  the removed optional `hpke-rs` libcrux HPKE chain stays absent.
- The monitor runs `cargo-deny`.
- The monitor runs `cargo update --dry-run` so maintainers can see available
  updates without changing either lockfile.
- Cryptographic standards are watched separately by
  `docs/security/crypto-source-watchlist.md` and
  `.github/workflows/crypto-source-monitor.yml`.

Release rule:

- Critical vulnerabilities get an urgent dependency PR and a full release gate.
- Normal minor and patch updates are grouped into reviewable PRs.
- Major updates are not grouped into automatic normal updates. They require a
  separate design/review because cryptographic behavior or wire compatibility
  may change.
- A dependency PR may be merged only after the Rust tests, local attack gates,
  vulnerability checks, dependency policy, and documentation checks pass.

This is intentionally not a direct production auto-update system. The monitor
is allowed to warn, fail CI, and prepare PRs. It is not allowed to silently
change the release branch.

## Русский

Umbrella Protocol теперь использует живой мониторинг зависимостей, но обновления
не вливает в `main` автоматически.

Что запускается:

- Dependabot каждый день проверяет корневые Rust-зависимости.
- Dependabot каждый день проверяет отдельный fuzz `Cargo.lock`.
- Dependabot раз в неделю проверяет GitHub Actions.
- `.github/workflows/dependency-monitor.yml` запускается каждые шесть часов и на
  важных pull request.
- Сторож запускает `cargo audit` для корневого lockfile и для
  `crates/umbrella-fuzz/fuzz/Cargo.lock`.
- Сторож запускает местные ворота PQ/backend, включая проверку, что удалённая
  optional libcrux HPKE-цепочка из `hpke-rs` не вернулась.
- Сторож запускает `cargo-deny`.
- Сторож запускает `cargo update --dry-run`, чтобы видеть доступные обновления
  без изменения lockfile.
- Криптографические стандарты отслеживаются отдельно через
  `docs/security/crypto-source-watchlist.md` и
  `.github/workflows/crypto-source-monitor.yml`.

Правило выпуска:

- Критическая уязвимость получает срочный PR с обновлением и полный выпускной
  прогон.
- Обычные минорные и patch-обновления группируются в проверяемые PR.
- Крупные обновления не попадают в обычный автоматический поток. Для них нужен
  отдельный разбор, потому что может измениться криптографическое поведение или
  совместимость форматов.
- PR с зависимостями можно вливать только после прохождения Rust-тестов,
  локальных атакующих ворот, проверки уязвимостей, политики зависимостей и
  проверки документов.

Это специально не система прямого автообновления боя. Сторож может предупреждать,
ронять CI и готовить PR. Он не может тихо менять выпускную ветку.
