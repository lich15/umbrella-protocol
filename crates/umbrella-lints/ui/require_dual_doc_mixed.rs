// UI-сценарий 7 (negative): docstring имеет и кириллицу, и латиницу —
// `require_dual_doc` НЕ должен срабатывать.
// UI scenario 7 (negative): the docstring has both Cyrillic and Latin
// — `require_dual_doc` must NOT fire.

#![allow(dead_code)]

/// Возвращает ответ. / Returns the answer.
pub fn answer() -> u32 {
    42
}

/// Публичная структура. / A public struct.
pub struct Holder {
    pub value: u32,
}

fn main() {}
