// UI-сценарий 6 (positive): docstring содержит только кириллицу — lint
// `require_dual_doc` обязан сработать.
// UI scenario 6 (positive): the docstring contains only Cyrillic text —
// the `require_dual_doc` lint must fire.

#![allow(dead_code)]

/// Возвращает ответ на главный вопрос.
pub fn ответ() -> u32 {
    42
}

/// Публичная структура с документацией только на русском.
pub struct Хранитель {
    pub значение: u32,
}

fn main() {}
