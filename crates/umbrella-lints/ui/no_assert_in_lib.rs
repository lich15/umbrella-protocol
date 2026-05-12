// compile-flags: --crate-type=lib
//
// UI-сценарий positive: `assert!()` в библиотечной функции должен
// подсветить `no_assert_in_lib`. Покрывает Этап 11 блок 11.8 + ADR-015
// §Решение 5 криterio 5.
// UI scenario positive: `assert!()` in a library function must trigger
// `no_assert_in_lib`. Covers Stage 11 block 11.8 + ADR-015 §Decision 5
// criterion 5.

#![allow(dead_code, clippy::assertions_on_constants)]

pub fn validate_invariant(input_len: usize) {
    assert!(input_len <= 4096);
}

pub fn validate_with_message(value: i32) {
    assert!(value >= 0, "value must be non-negative");
}
