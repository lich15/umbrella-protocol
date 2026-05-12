// compile-flags: --crate-type=lib
//
// UI-сценарий negative: `todo!()` внутри `#[cfg(test)] mod` — pass.
// Несмотря на это правило не fires в тестах (они placeholder для
// будущих ассертов), мы всё равно избегаем `todo!()` в реальных тестах
// per QUALITY_STANDARDS §1 §3.
// UI scenario negative: `todo!()` inside `#[cfg(test)] mod` — pass.
// Even though the rule does not fire in tests (they are placeholders
// for future asserts), we still avoid `todo!()` in real tests per
// QUALITY_STANDARDS §1 §3.

#![allow(dead_code)]

pub fn pure_lib_function(value: i32) -> i32 {
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "placeholder test for future implementation"]
    fn todo_inside_test_is_allowed() {
        let _ = pure_lib_function(0);
        todo!("flesh this test out later")
    }
}
