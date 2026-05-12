// compile-flags: --crate-type=lib
//
// UI-сценарий 3 (positive): `.unwrap()` и `.expect(_)` в библиотечной
// функции должны подсветить `no_unwrap_in_lib`. Header
// `--crate-type=lib` заставляет compiletest считать файл библиотекой
// (иначе lint пропустит binary-крейт).
// UI scenario 3 (positive): `.unwrap()` and `.expect(_)` in a library
// function must trigger `no_unwrap_in_lib`. The `--crate-type=lib`
// header tells compiletest to treat the file as a library (otherwise
// the lint skips binary crates).

#![allow(dead_code, clippy::unnecessary_wraps)]

pub fn lookup(value: Option<u32>) -> u32 {
    value.unwrap()
}

pub fn explain(value: Option<u32>) -> u32 {
    value.expect("value is required")
}
