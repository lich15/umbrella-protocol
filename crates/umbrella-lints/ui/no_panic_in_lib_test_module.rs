// compile-flags: --crate-type=lib
//
// UI-сценарий negative: `panic!()` внутри `#[cfg(test)] mod` —
// dylint детектит контекст теста через `clippy_utils::is_in_test` и
// пропускает emit lint. Заголовок `--crate-type=lib` нужен, чтобы сам
// фильтр «library crate» сработал.
// UI scenario negative: `panic!()` inside `#[cfg(test)] mod` — dylint
// detects the test context via `clippy_utils::is_in_test` and skips
// the lint. The `--crate-type=lib` header is required so the
// "library crate" filter triggers.

#![allow(dead_code)]

pub fn pure_lib_function(value: i32) -> i32 {
    value.saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_inside_test_is_allowed() {
        if pure_lib_function(0) != 1 {
            panic!("invariant violated in test only");
        }
    }
}
