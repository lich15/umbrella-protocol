// compile-flags: --crate-type=lib
//
// UI-сценарий positive: `todo!()` в библиотечной функции должен
// подсветить `no_todo_in_lib`. Покрывает Этап 11 блок 11.8 + ADR-015
// §Решение 5 криterio 5 + QUALITY_STANDARDS §1 §3.
// UI scenario positive: `todo!()` in a library function must trigger
// `no_todo_in_lib`. Covers Stage 11 block 11.8 + ADR-015 §Decision 5
// criterion 5 + QUALITY_STANDARDS §1 §3.

#![allow(dead_code, clippy::diverging_sub_expression)]

pub fn parse_payload(_input: &[u8]) -> Result<u32, &'static str> {
    todo!()
}
