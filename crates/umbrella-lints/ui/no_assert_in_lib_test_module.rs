// compile-flags: --crate-type=lib
//
// UI-сценарий negative: `assert!()` внутри `#[cfg(test)] mod` — pass.
// UI scenario negative: `assert!()` inside `#[cfg(test)] mod` — pass.

#![allow(dead_code)]

pub fn pure_lib_function(value: i32) -> i32 {
    value.saturating_mul(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_inside_test_is_allowed() {
        assert!(pure_lib_function(2) == 4);
    }
}
