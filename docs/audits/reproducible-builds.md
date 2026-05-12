# Reproducible Builds

[English](#english) | [Русский](#русский)

## English

Release builds use deterministic settings where the target platform allows it.

## Rust Release Profile

The workspace release profile uses:

- fat LTO;
- one codegen unit;
- stripped symbols;
- aborting panics.

## Verification

```bash
cargo build --workspace --release --locked
```

Release artifacts should be accompanied by the checked-in manifest and SBOM
under `docs/security`. Platform packaging for iOS and Android is verified by
the dedicated FFI workflows.

---

## Русский

Release-сборки используют детерминированные настройки там, где это позволяет
целевая платформа.

## Rust release profile

Workspace release profile использует:

- fat LTO;
- один codegen unit;
- stripped symbols;
- aborting panics.

## Проверка

```bash
cargo build --workspace --release --locked
```

Release artifacts должны сопровождаться зафиксированным манифестом и SBOM в
`docs/security`. Платформенная упаковка для iOS и Android проверяется
отдельными FFI workflow.
