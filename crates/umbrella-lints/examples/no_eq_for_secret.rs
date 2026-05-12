// UI-сценарий 1 (positive): тип `Secret` реализует `ZeroizeOnDrop`,
// поэтому сравнение через `==` обязано подсветить lint
// `no_eq_for_secret`.
// UI scenario 1 (positive): the `Secret` type implements
// `ZeroizeOnDrop`, so comparing it via `==` must trigger the
// `no_eq_for_secret` lint.

#![allow(dead_code)]

use zeroize::{Zeroize, ZeroizeOnDrop};

struct Secret([u8; 32]);

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Secret {}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

fn check_secret(a: &Secret, b: &Secret) -> bool {
    *a == *b
}

fn refuse_secret(a: &Secret, b: &Secret) -> bool {
    *a != *b
}

fn main() {
    let a = Secret([0u8; 32]);
    let b = Secret([0u8; 32]);
    let _ = check_secret(&a, &b);
    let _ = refuse_secret(&a, &b);
}
