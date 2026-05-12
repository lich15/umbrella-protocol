//! Lint `no_assert_in_lib` — запрещает макрос `assert!()` в библиотечном
//! коде.
//! Lint `no_assert_in_lib` — forbids the `assert!()` macro in library
//! code.
//!
//! Этап 11 — пост-1.0 операционный трек, блок 11.8 (closure ADR-015
//! §Решение 5 криterio 5 «zero panics в lib code»).
//! Stage 11 — post-1.0 operational track, block 11.8 (closing ADR-015
//! §Decision 5 criterion 5 "zero panics in lib code").
//!
//! Покрывает только `assert!()` (диагностический symbol
//! `assert_macro`). `debug_assert!()` остаётся разрешённым потому что
//! компилируется в no-op в `--release` сборке (нет panic в production).
//! `assert_eq!()` / `assert_ne!()` имеют отдельные диагностические items
//! и не покрываются этим правилом.
//! Covers only `assert!()` (diagnostic symbol `assert_macro`).
//! `debug_assert!()` remains allowed because it compiles to a no-op in
//! `--release` (no panic in production). `assert_eq!()` / `assert_ne!()`
//! have separate diagnostic items and are not covered by this rule.

use clippy_utils::diagnostics::span_lint_and_note;
use clippy_utils::macros::root_macro_call_first_node;
use rustc_hir::Expr;
use rustc_lint::{LateContext, LateLintPass};
use rustc_session::{declare_lint, impl_lint_pass};
use rustc_span::sym;

use crate::is_library_crate;

declare_lint! {
    /// ### Что делает / What it does
    /// Запрещает макрос `assert!()` в библиотечных крейтах. `#[cfg(test)]`
    /// модули игнорируются — там `assert!()` это идиоматичный test-tool.
    ///
    /// Forbids the `assert!()` macro in library crates. `#[cfg(test)]`
    /// modules are ignored — there `assert!()` is the idiomatic test
    /// tool.
    ///
    /// ### Почему это плохо / Why is this bad?
    /// `assert!(cond)` в production lib коде эквивалентен `if !cond {
    /// panic!() }` — то есть панику может вызвать любой attacker-controlled
    /// input нарушающий cond. Все три риска `panic!()` применимы (см.
    /// `no_panic_in_lib`): DoS, утечка секрета через panic message,
    /// timing-канал. ADR-015 §Решение 5 криterio 5 — «zero panics в lib
    /// code» — assertions включены.
    ///
    /// `assert!(cond)` in production library code is equivalent to `if
    /// !cond { panic!() }` — meaning a panic can be triggered by any
    /// attacker-controlled input that violates `cond`. All three
    /// `panic!()` risks apply (see `no_panic_in_lib`): DoS, secret leak
    /// through panic message, timing channel. ADR-015 §Decision 5
    /// criterion 5 — "zero panics in lib code" — covers assertions.
    ///
    /// ### Как исправить / How to fix
    /// - Если условие — runtime invariant (зависит от внешнего ввода) —
    ///   вернуть `Result::Err(SomeError::SpecificCase)` через `if !cond
    ///   { return Err(...); }`.
    /// - Если условие — compile-time invariant (никогда не нарушается
    ///   при корректном API) — заменить на `debug_assert!()` (no-op в
    ///   release) либо устранить через type-system (newtypes / phantom
    ///   types / sealed traits).
    ///
    /// - If the condition is a runtime invariant (depends on external
    ///   input) — return `Result::Err(SomeError::SpecificCase)` via `if
    ///   !cond { return Err(...); }`.
    /// - If the condition is a compile-time invariant (never violated
    ///   with a correct API) — replace with `debug_assert!()` (no-op in
    ///   release) or eliminate through the type system (newtypes /
    ///   phantom types / sealed traits).
    pub NO_ASSERT_IN_LIB,
    Warn,
    "use of `assert!()` macro in lib code (panic vector — same risks as `panic!()`)"
}

pub struct NoAssertInLib;

impl_lint_pass!(NoAssertInLib => [NO_ASSERT_IN_LIB]);

impl<'tcx> LateLintPass<'tcx> for NoAssertInLib {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let Some(macro_call) = root_macro_call_first_node(cx, expr) else {
            return;
        };
        let Some(diag_name) = cx.tcx.get_diagnostic_name(macro_call.def_id) else {
            return;
        };
        if diag_name != sym::assert_macro {
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
            NO_ASSERT_IN_LIB,
            macro_call.span,
            "`assert!()` is not allowed in library code (ADR-015 §Decision 5 criterion 5: assertions are panic vectors)",
            None,
            "return `Result::Err(...)` if the condition is a runtime invariant; \
             use `debug_assert!()` (no-op in release) for invariants that are guaranteed by a correct API; \
             prefer type-system invariants (newtypes / phantom types / sealed traits) where possible",
        );
    }
}
