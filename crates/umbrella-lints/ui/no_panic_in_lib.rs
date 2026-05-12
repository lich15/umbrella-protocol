// compile-flags: --crate-type=lib
//
// UI-сценарий positive: `panic!()` в библиотечной функции должен
// подсветить `no_panic_in_lib`. Header `--crate-type=lib` заставляет
// compiletest считать файл библиотекой (иначе lint пропустит binary
// крейт). Покрывает Этап 11 блок 11.8 + ADR-015 §Решение 5 криterio 5.
// UI scenario positive: `panic!()` in a library function must trigger
// `no_panic_in_lib`. The `--crate-type=lib` header tells compiletest to
// treat the file as a library (otherwise the lint skips binary crates).
// Covers Stage 11 block 11.8 + ADR-015 §Decision 5 criterion 5.

#![allow(dead_code, clippy::needless_pass_by_value, clippy::diverging_sub_expression)]

pub fn fail_unconditional() -> u32 {
    panic!("never returns")
}

pub fn fail_with_format(reason: String) -> u32 {
    panic!("failure: {}", reason)
}
