// compile-flags: --crate-type=lib
//
// UI-сценарий positive: `unreachable!()` в библиотечной функции должен
// подсветить `no_unreachable_in_lib`. Покрывает Этап 11 блок 11.8 +
// ADR-015 §Решение 5 криterio 5.
// UI scenario positive: `unreachable!()` in a library function must
// trigger `no_unreachable_in_lib`. Covers Stage 11 block 11.8 + ADR-015
// §Decision 5 criterion 5.

#![allow(dead_code, clippy::diverging_sub_expression)]

pub enum Mode {
    Cloud,
    Secret,
}

pub fn dispatch(mode: Mode) -> &'static str {
    match mode {
        Mode::Cloud => "cloud",
        Mode::Secret => "secret",
        #[allow(unreachable_patterns)]
        _ => unreachable!("Mode is exhaustive"),
    }
}
