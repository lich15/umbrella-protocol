// compile-flags: --crate-type=lib
//
// UI-сценарий positive: `unimplemented!()` в библиотечной функции должен
// подсветить `no_unimplemented_in_lib`. Покрывает Этап 11 блок 11.8 +
// ADR-015 §Решение 5 криterio 5 + QUALITY_STANDARDS §1 §3.
// UI scenario positive: `unimplemented!()` in a library function must
// trigger `no_unimplemented_in_lib`. Covers Stage 11 block 11.8 + ADR-015
// §Decision 5 criterion 5 + QUALITY_STANDARDS §1 §3.

#![allow(dead_code, clippy::diverging_sub_expression)]

pub trait MessageStore {
    fn fetch(&self, id: u64) -> Vec<u8>;
}

pub struct StubStore;

impl MessageStore for StubStore {
    fn fetch(&self, _id: u64) -> Vec<u8> {
        unimplemented!()
    }
}
