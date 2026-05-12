// UI-сценарий 2 (negative): обычный `u32` не реализует `Zeroize`, поэтому
// сравнение через `==` НЕ должно подсветить `no_eq_for_secret`.
// UI scenario 2 (negative): a plain `u32` does not implement `Zeroize`, so
// comparing it via `==` must NOT trigger `no_eq_for_secret`.

#![allow(dead_code)]

fn compare_numbers(a: u32, b: u32) -> bool {
    a == b
}

fn main() {
    let _ = compare_numbers(1, 2);
}
