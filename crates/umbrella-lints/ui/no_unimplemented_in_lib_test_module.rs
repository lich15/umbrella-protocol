// compile-flags: --crate-type=lib
//
// UI-сценарий negative: `unimplemented!()` внутри `#[cfg(test)] mod` — pass.
// UI scenario negative: `unimplemented!()` inside `#[cfg(test)] mod` — pass.

#![allow(dead_code)]

pub fn pure_lib_function(value: i32) -> i32 {
    value.saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "stub test scaffold for future implementation"]
    fn unimplemented_inside_test_is_allowed() {
        let _ = pure_lib_function(0);
        unimplemented!("test scaffold")
    }
}
