// compile-flags: --crate-type=lib
//
// UI-сценарий negative: `unreachable!()` внутри `#[cfg(test)] mod` — pass.
// UI scenario negative: `unreachable!()` inside `#[cfg(test)] mod` — pass.

#![allow(dead_code)]

pub fn pure_lib_function(flag: bool) -> i32 {
    if flag { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_inside_test_is_allowed() {
        match pure_lib_function(true) {
            1 => {}
            0 => {}
            _ => unreachable!("only 0 or 1 expected"),
        }
    }
}
