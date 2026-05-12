//! Lint `no_panic_in_lib` — запрещает макрос `panic!()` в библиотечном
//! коде.
//! Lint `no_panic_in_lib` — forbids the `panic!()` macro in library code.
//!
//! Этап 11 — пост-1.0 операционный трек, блок 11.8 (closure ADR-015
//! §Решение 5 криterio 5 «zero panics в lib code»).
//! Stage 11 — post-1.0 operational track, block 11.8 (closing ADR-015
//! §Decision 5 criterion 5 "zero panics in lib code").
//!
//! Покрывает edition 2015 и edition 2021 формы macro (через
//! [`clippy_utils::macros::is_panic`], которая матчит оба
//! `core_panic_macro` и `std_panic_macro` диагностических symbol).
//! Covers edition 2015 and edition 2021 forms of the macro (via
//! [`clippy_utils::macros::is_panic`], which matches both
//! `core_panic_macro` and `std_panic_macro` diagnostic symbols).

use clippy_utils::diagnostics::span_lint_and_note;
use clippy_utils::macros::{is_panic, root_macro_call_first_node};
use rustc_hir::Expr;
use rustc_lint::{LateContext, LateLintPass};
use rustc_session::{declare_lint, impl_lint_pass};

use crate::is_library_crate;

declare_lint! {
    /// ### Что делает / What it does
    /// Запрещает макрос `panic!()` (включая edition 2021 и edition 2015
    /// формы) в библиотечных крейтах (тех, чей `crate-type` содержит
    /// `lib`/`rlib`/`dylib`/`cdylib`/`staticlib`). Чисто бинарные крейты
    /// и `#[cfg(test)]`-блоки игнорируются.
    ///
    /// Forbids the `panic!()` macro (including edition 2021 and edition
    /// 2015 forms) in library crates (those whose `crate-type` contains
    /// `lib`/`rlib`/`dylib`/`cdylib`/`staticlib`). Pure binary crates and
    /// `#[cfg(test)]` blocks are ignored.
    ///
    /// ### Почему это плохо / Why is this bad?
    /// ADR-015 §Решение 5 криterio 5 — «zero panics в lib code».
    /// QUALITY_STANDARDS §1 §3 «Запрещено `panic!()` за исключением
    /// unreachable-branches после compile-time guarantee». Три конкретных
    /// риска при вторжении противника уровня D из SPEC-01 § 4:
    ///
    /// 1. **Отказ в обслуживании** (rows 1+2): malformed wire-input →
    ///    panic в parser → crash сервера либо клиента → DoS for 1B users.
    /// 2. **Утечка секрета через panic message** (row 11): payload может
    ///    содержать part of master-key либо plaintext, который попадает
    ///    в stderr / process journal через `Display`-форматирование
    ///    panic-аргумента или через стек-фрейм при `RUST_BACKTRACE=1`.
    /// 3. **Timing side-channel** (rows 11+13): panic-обработка в Rust
    ///    значительно дольше `Result::Err` пути (unwinder + drop chain +
    ///    panic hook); противник распознаёт valid input от invalid через
    ///    замер времени.
    ///
    /// ADR-015 §Decision 5 criterion 5 — "zero panics in lib code".
    /// QUALITY_STANDARDS §1 §3 — "no `panic!()` except for
    /// unreachable-branches after compile-time guarantee". Three concrete
    /// risks under SPEC-01 level-D adversary intrusion:
    /// 1. **Denial of service** (rows 1+2): malformed wire-input → panic
    ///    in the parser → crash → DoS for 1B users.
    /// 2. **Secret leak via panic message** (row 11): the payload may
    ///    contain part of a master-key or plaintext that lands in stderr
    ///    or the process journal via `Display`-formatting of the panic
    ///    argument or stack frames under `RUST_BACKTRACE=1`.
    /// 3. **Timing side-channel** (rows 11+13): Rust panic handling is
    ///    much slower than the `Result::Err` path (unwinder + drop chain
    ///    + panic hook); an adversary distinguishes valid input from
    ///    invalid via timing.
    ///
    /// ### Как исправить / How to fix
    /// Вернуть `Result::Err(SomeError::SpecificCase)` с конкретным
    /// вариантом ошибки. Если panic невозможен по type-system invariant —
    /// убедиться что инвариант enforced compile-time (sealed trait /
    /// exhaustive match без `_ => panic!()`).
    ///
    /// Return `Result::Err(SomeError::SpecificCase)` with a concrete
    /// variant. If a panic is impossible due to a type-system invariant,
    /// ensure the invariant is enforced at compile-time (sealed traits /
    /// exhaustive matches without `_ => panic!()`).
    pub NO_PANIC_IN_LIB,
    Warn,
    "use of `panic!()` macro in lib code (DoS + secret leak via message + timing channel)"
}

pub struct NoPanicInLib;

impl_lint_pass!(NoPanicInLib => [NO_PANIC_IN_LIB]);

impl<'tcx> LateLintPass<'tcx> for NoPanicInLib {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let Some(macro_call) = root_macro_call_first_node(cx, expr) else {
            return;
        };
        if !is_panic(cx, macro_call.def_id) {
            return;
        }
        if !is_library_crate(cx) {
            return;
        }
        if clippy_utils::is_in_test(cx.tcx, expr.hir_id) {
            return;
        }

        span_lint_and_note(
            cx,
            NO_PANIC_IN_LIB,
            macro_call.span,
            "`panic!()` is not allowed in library code (ADR-015 §Decision 5 criterion 5: zero panics in lib code)",
            None,
            "return `Result::Err(SomeError::SpecificCase)` with a concrete variant; \
             panic in library code can: (1) DoS users via malformed wire input, \
             (2) leak secrets through panic message and stack frames, \
             (3) create timing side-channel (panic handling is slower than the `Err` path)",
        );
    }
}
