# NIST KAT Vector Sources

[English](#english) | [Русский](#русский)

## English

This directory contains checked-in stability vectors for the `umbrella-pq`
post-quantum primitives. The vectors are read-only release artifacts: changing a
vector requires updating `../CHECKSUMS.txt` in the same review.

## Checked-In Stability Vectors

| File | Algorithm | Purpose |
|---|---|---|
| `stability-ml-kem-768.json` | ML-KEM-768 | Locks the local `umbrella-pq` behavior used by regression tests. |
| `stability-x-wing.json` | X-Wing draft-10-compatible | Locks the local `umbrella-pq::xwing` combiner behavior; the draft-10 KAT is also covered by `crates/umbrella-pq/tests/xwing_draft10_kat.rs`. |
| `stability-ml-dsa-65.json` | ML-DSA-65 | Locks deterministic key generation and verification acceptance. ML-DSA signing uses hedged randomness, so signatures are not expected to be deterministic for fixed seeds. |
| `stability-slh-dsa-128f.json` | SLH-DSA-128f-simple | Locks deterministic key generation and verification acceptance with the same hedged-signing caveat. |

These stability vectors do not replace official NIST ACVP vectors. They are a
repository-level regression guard against silent behavior drift when
post-quantum dependencies change.

## External Reference Sources

Reviewers who want to compare against public upstream material can use:

- ML-KEM FIPS 203 ACVP material:
  `https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203`
- ML-DSA FIPS 204 ACVP material:
  `https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204`
- SLH-DSA FIPS 205 ACVP material:
  `https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-keyGen-FIPS205`
- X-Wing draft material:
  `https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/`

When new vectors are added, keep the raw source URL, conversion method, and
SHA-256 checksum in the same change.

---

## Русский

Эта папка содержит зафиксированные stability vectors для post-quantum
примитивов `umbrella-pq`. Векторы являются read-only release artifacts: при
изменении любого вектора нужно в том же review обновлять `../CHECKSUMS.txt`.

## Зафиксированные stability vectors

| Файл | Алгоритм | Назначение |
|---|---|---|
| `stability-ml-kem-768.json` | ML-KEM-768 | Закрепляет локальное поведение `umbrella-pq`, используемое регрессионными тестами. |
| `stability-x-wing.json` | X-Wing draft-10-compatible | Закрепляет локальное поведение combiner `umbrella-pq::xwing`; draft-10 KAT также покрыт тестом `crates/umbrella-pq/tests/xwing_draft10_kat.rs`. |
| `stability-ml-dsa-65.json` | ML-DSA-65 | Закрепляет детерминированную генерацию ключей и принятие корректной подписи. ML-DSA signing использует hedged randomness, поэтому подписи не обязаны быть детерминированными при fixed seeds. |
| `stability-slh-dsa-128f.json` | SLH-DSA-128f-simple | Закрепляет детерминированную генерацию ключей и принятие корректной подписи с той же оговоркой про hedged signing. |

Эти stability vectors не заменяют официальные NIST ACVP vectors. Они являются
репозиторным регрессионным барьером от тихого изменения поведения при обновлении
post-quantum зависимостей.

## Внешние источники для сверки

Ревьюеры, которые хотят свериться с публичными upstream-материалами, могут
использовать:

- ML-KEM FIPS 203 ACVP material:
  `https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203`
- ML-DSA FIPS 204 ACVP material:
  `https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204`
- SLH-DSA FIPS 205 ACVP material:
  `https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-keyGen-FIPS205`
- X-Wing draft material:
  `https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/`

При добавлении новых vectors держите raw source URL, способ конвертации и
SHA-256 checksum в одном изменении.
