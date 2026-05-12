//! Lint `no_unimplemented_in_lib` — запрещает макрос `unimplemented!()`
//! в библиотечном коде.
//! Lint `no_unimplemented_in_lib` — forbids the `unimplemented!()` macro
//! in library code.
//!
//! Этап 11 — пост-1.0 операционный трек, блок 11.8 (closure ADR-015
//! §Решение 5 криterio 5 «zero panics в lib code» + QUALITY_STANDARDS §1
//! §3 запрет на «упрощённую версию», «временную реализацию»).
//! Stage 11 — post-1.0 operational track, block 11.8 (closing ADR-015
//! §Decision 5 criterion 5 "zero panics in lib code" + QUALITY_STANDARDS
//! §1 §3 ban on "simplified version", "temporary implementation").

use clippy_utils::diagnostics::span_lint_and_note;
use clippy_utils::macros::root_macro_call_first_node;
use rustc_hir::Expr;
use rustc_lint::{LateContext, LateLintPass};
use rustc_session::{declare_lint, impl_lint_pass};
use rustc_span::sym;

use crate::is_library_crate;

declare_lint! {
    /// ### Что делает / What it does
    /// Запрещает макрос `unimplemented!()` в библиотечных крейтах.
    /// `#[cfg(test)]` модули игнорируются.
    ///
    /// Forbids the `unimplemented!()` macro in library crates.
    /// `#[cfg(test)]` modules are ignored.
    ///
    /// ### Почему это плохо / Why is this bad?
    /// `unimplemented!()` отличается от `todo!()` только семантически
    /// («не реализовано» vs «будет реализовано позже»), но runtime
    /// поведение идентичное — panic. QUALITY_STANDARDS §1 §3 «Запрещено:
    /// упрощённая версия, временная реализация, quick and dirty». Postulate
    /// 3 «Максимум, не минимум — production senior+ с первого коммита
    /// без черновой версии». ADR-015 §Решение 5 криterio 5 «zero panics
    /// в lib code».
    ///
    /// `unimplemented!()` differs from `todo!()` only semantically ("not
    /// implemented" vs "will be implemented later"), but the runtime
    /// behavior is identical — a panic. QUALITY_STANDARDS §1 §3 — "no
    /// simplified version, no temporary implementation, no quick and
    /// dirty". Postulate 3 — "Maximum, not minimum — senior+
    /// production-ready code from the first commit, no draft phase".
    /// ADR-015 §Decision 5 criterion 5 — "zero panics in lib code".
    ///
    /// ### Как исправить / How to fix
    /// Реализовать функцию полностью либо удалить её из библиотечной
    /// поверхности. Если функция должна сигнализировать что данная
    /// конкретная конфигурация / feature не поддерживается в текущей
    /// сборке — вернуть `Result::Err(SomeError::FeatureUnsupported {
    /// reason: "..." })` с конкретным вариантом ошибки, не panic.
    ///
    /// Implement the function fully or remove it from the library
    /// surface. If the function should signal that this specific
    /// configuration / feature is unsupported in the current build —
    /// return `Result::Err(SomeError::FeatureUnsupported { reason: "..." })`
    /// with a concrete error variant, not a panic.
    pub NO_UNIMPLEMENTED_IN_LIB,
    Warn,
    "use of `unimplemented!()` macro in lib code (production must be complete; panic vector)"
}

pub struct NoUnimplementedInLib;

impl_lint_pass!(NoUnimplementedInLib => [NO_UNIMPLEMENTED_IN_LIB]);

impl<'tcx> LateLintPass<'tcx> for NoUnimplementedInLib {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let Some(macro_call) = root_macro_call_first_node(cx, expr) else {
            return;
        };
        let Some(diag_name) = cx.tcx.get_diagnostic_name(macro_call.def_id) else {
            return;
        };
        if diag_name != sym::unimplemented_macro {
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
            NO_UNIMPLEMENTED_IN_LIB,
            macro_call.span,
            "`unimplemented!()` is not allowed in library code (QUALITY_STANDARDS §1 §3: production must be complete; panic vector)",
            None,
            "implement the function fully, remove it from the library surface, \
             or return `Result::Err(SomeError::FeatureUnsupported { reason: \"...\" })` with a concrete variant if signalling a build-config gap; \
             see QUALITY_STANDARDS §1 §3 «упрощённая версия запрещена» + ADR-015 §Decision 5 criterion 5",
        );
    }
}
