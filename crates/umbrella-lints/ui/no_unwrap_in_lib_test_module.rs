// compile-flags: --crate-type=lib
//
// UI-сценарий 4 (negative): `.unwrap()` внутри `#[cfg(test)] mod` —
// dylint детектит контекст теста через `clippy_utils::is_in_test`
// и пропускает emit lint. Заголовок `--crate-type=lib` нужен, чтобы
// сам filter «library crate» сработал (иначе lint вообще не запустится
// и тест станет ложно-зелёным).
// UI scenario 4 (negative): `.unwrap()` inside `#[cfg(test)] mod` —
// dylint detects the test context via `clippy_utils::is_in_test` and
// skips the lint. The `--crate-type=lib` header is required so the
// "library crate" filter triggers (otherwise the lint never runs and
// the test would be a false-green).

#![allow(dead_code)]

pub fn pure_lib_function(value: Option<u32>) -> Option<u32> {
    value.map(|v| v + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap_inside_test_is_allowed() {
        let v = pure_lib_function(Some(1)).unwrap();
        assert_eq!(v, 2);
    }
}
