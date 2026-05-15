# Umbrella patch for hpke-rs 0.6.1

## По-русски

Эта папка содержит локальную заплатку для `hpke-rs 0.6.1`.

Причина: Umbrella через `openmls_rust_crypto 0.5.1` использует RustCrypto-бэкенд
HPKE. Неиспользуемый optional-бэкенд `hpke-rs-libcrux` всё равно попадал в
`Cargo.lock` и SBOM, а он тянул `libcrux-chacha20poly1305 <0.0.8`
(`RUSTSEC-2026-0124`).

Что изменено:

- удалена зависимость `hpke-rs-libcrux` из графа зависимостей;
- имя feature `libcrux` оставлено пустым, чтобы случайное включение не проходило
  тихо как “боевой” путь;
- исходный HPKE-код и используемый RustCrypto-путь не менялись.

Когда upstream выпустит `hpke-rs` без уязвимой optional-цепочки, эту заплатку
нужно удалить и вернуться на обычную crates.io-зависимость.

## English

This directory contains a local Umbrella patch for `hpke-rs 0.6.1`.

Reason: Umbrella uses the RustCrypto HPKE backend through
`openmls_rust_crypto 0.5.1`. The unused optional `hpke-rs-libcrux` backend was
still recorded in `Cargo.lock` and SBOM, and it pulled
`libcrux-chacha20poly1305 <0.0.8` (`RUSTSEC-2026-0124`).

Changes:

- removed the `hpke-rs-libcrux` dependency from the dependency graph;
- kept the `libcrux` feature name empty so accidental use does not silently look
  production-ready;
- did not change HPKE source code or the RustCrypto path Umbrella uses.

Once upstream ships `hpke-rs` without the vulnerable optional chain, remove this
patch and return to the normal crates.io dependency.
