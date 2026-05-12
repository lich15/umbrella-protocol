//! Lint `no_unreachable_in_lib` — запрещает макрос `unreachable!()` в
//! библиотечном коде.
//! Lint `no_unreachable_in_lib` — forbids the `unreachable!()` macro in
//! library code.
//!
//! Этап 11 — пост-1.0 операционный трек, блок 11.8 (closure ADR-015
//! §Решение 5 криterio 5 «zero panics в lib code»).
//! Stage 11 — post-1.0 operational track, block 11.8 (closing ADR-015
//! §Decision 5 criterion 5 "zero panics in lib code").

use clippy_utils::diagnostics::span_lint_and_note;
use clippy_utils::macros::root_macro_call_first_node;
use rustc_hir::Expr;
use rustc_lint::{LateContext, LateLintPass};
use rustc_session::{declare_lint, impl_lint_pass};
use rustc_span::sym;

use crate::is_library_crate;

declare_lint! {
    /// ### Что делает / What it does
    /// Запрещает макрос `unreachable!()` в библиотечных крейтах.
    /// `#[cfg(test)]` модули игнорируются.
    ///
    /// Forbids the `unreachable!()` macro in library crates. `#[cfg(test)]`
    /// modules are ignored.
    ///
    /// ### Почему это плохо / Why is this bad?
    /// `unreachable!()` — это assertion «эта точка кода никогда не
    /// достижима», но если предположение нарушится из-за refactor
    /// либо неучтённого input — выполнение приведёт к panic. ADR-015
    /// §Решение 5 криterio 5 — «zero panics в lib code» — включает
    /// `unreachable!()`. Те же три риска что у `panic!()`: DoS, утечка
    /// секрета через panic message, timing-канал.
    ///
    /// `unreachable!()` is an "this code path is never reached"
    /// assertion, but if the assumption breaks due to a refactor or an
    /// un-handled input — execution leads to a panic. ADR-015 §Decision 5
    /// criterion 5 — "zero panics in lib code" — covers `unreachable!()`.
    /// Same three risks as `panic!()`: DoS, secret leak through panic
    /// message, timing channel.
    ///
    /// ### Как исправить / How to fix
    /// - Express unreachability через type system: `Infallible` / sealed
    ///   traits / exhaustive match со всеми вариантами enum закрытыми.
    /// - Если случай реально может встречаться (например malformed
    ///   wire-input) — вернуть `Result::Err(SomeError::SpecificCase)`
    ///   вместо panic.
    /// - Если необходимо явно отметить unreachable путь без runtime
    ///   panic — использовать `debug_assert!(false, "...")` либо
    ///   `core::hint::unreachable_unchecked()` (только под `unsafe`
    ///   с математическим обоснованием инварианта).
    ///
    /// - Express unreachability through the type system: `Infallible` /
    ///   sealed traits / exhaustive matches with all enum variants
    ///   covered.
    /// - If the case can actually occur (e.g., malformed wire-input) —
    ///   return `Result::Err(SomeError::SpecificCase)` instead of a
    ///   panic.
    /// - If you must explicitly mark an unreachable path without a
    ///   runtime panic — use `debug_assert!(false, "...")` or
    ///   `core::hint::unreachable_unchecked()` (only inside `unsafe`,
    ///   with a mathematical justification of the invariant).
    pub NO_UNREACHABLE_IN_LIB,
    Warn,
    "use of `unreachable!()` macro in lib code (panic vector — same risks as `panic!()`)"
}

pub struct NoUnreachableInLib;

impl_lint_pass!(NoUnreachableInLib => [NO_UNREACHABLE_IN_LIB]);

impl<'tcx> LateLintPass<'tcx> for NoUnreachableInLib {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let Some(macro_call) = root_macro_call_first_node(cx, expr) else {
            return;
        };
        let Some(diag_name) = cx.tcx.get_diagnostic_name(macro_call.def_id) else {
            return;
        };
        if diag_name != sym::unreachable_macro {
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
            NO_UNREACHABLE_IN_LIB,
            macro_call.span,
            "`unreachable!()` is not allowed in library code (ADR-015 §Decision 5 criterion 5: panics on assumption breach)",
            None,
            "express unreachability through the type system (`Infallible`, sealed traits, exhaustive matches); \
             return `Result::Err(...)` for runtime cases that can actually occur; \
             use `debug_assert!(false, ...)` or `core::hint::unreachable_unchecked()` (under `unsafe` with a justification) if you must mark an impossible path without a runtime panic",
        );
    }
}
