// UI-сценарий 5 (positive): docstring содержит только латиницу — lint
// `require_dual_doc` обязан сработать.
// UI scenario 5 (positive): the docstring contains only Latin text — the
// `require_dual_doc` lint must fire.

#![allow(dead_code)]

/// Returns the answer to life, the universe, and everything.
pub fn answer() -> u32 {
    42
}

/// A simple public struct with English-only documentation.
pub struct Holder {
    pub value: u32,
}

fn main() {}
