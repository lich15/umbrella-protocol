//! Lint `no_todo_in_lib` — запрещает макрос `todo!()` в библиотечном
//! коде.
//! Lint `no_todo_in_lib` — forbids the `todo!()` macro in library code.
//!
//! Этап 11 — пост-1.0 операционный трек, блок 11.8 (closure ADR-015
//! §Решение 5 криterio 5 «zero panics в lib code» + QUALITY_STANDARDS §1
//! §3 запрет на «потом сделаем»).
//! Stage 11 — post-1.0 operational track, block 11.8 (closing ADR-015
//! §Decision 5 criterion 5 "zero panics in lib code" + QUALITY_STANDARDS
//! §1 §3 ban on "we'll do it later").

use clippy_utils::diagnostics::span_lint_and_note;
use clippy_utils::macros::root_macro_call_first_node;
use rustc_hir::Expr;
use rustc_lint::{LateContext, LateLintPass};
use rustc_session::{declare_lint, impl_lint_pass};
use rustc_span::sym;

use crate::is_library_crate;

declare_lint! {
    /// ### Что делает / What it does
    /// Запрещает макрос `todo!()` в библиотечных крейтах. `#[cfg(test)]`
    /// модули игнорируются (там `todo!()` иногда используется как
    /// placeholder в незаконченных тестах — но и в тестах лучше избегать).
    ///
    /// Forbids the `todo!()` macro in library crates. `#[cfg(test)]`
    /// modules are ignored (where `todo!()` is sometimes used as a
    /// placeholder in unfinished tests — though even in tests it should
    /// be avoided).
    ///
    /// ### Почему это плохо / Why is this bad?
    /// `todo!()` — это явная пометка «эту функцию я ещё не написал»,
    /// которая в production коде означает гарантированный panic если
    /// функцию вызовут. QUALITY_STANDARDS §1 §3 «Запрещено: TODO: proper
    /// implementation later, потом сделаем». Postulate 3 «Максимум, не
    /// минимум — каждая строка кода пишется сразу как production senior+
    /// готовая к внешнему аудиту. С первого коммита. Без этапа черновой
    /// версии». ADR-015 §Решение 5 криterio 5 «zero panics в lib code».
    ///
    /// `todo!()` is an explicit marker of "I haven't written this
    /// function yet" which in production code guarantees a panic if the
    /// function is called. QUALITY_STANDARDS §1 §3 — "no TODO: proper
    /// implementation later, no 'we'll do it later'". Postulate 3 —
    /// "Maximum, not minimum — every line is written as senior+
    /// production-ready code from the first commit. No draft phase".
    /// ADR-015 §Decision 5 criterion 5 — "zero panics in lib code".
    ///
    /// ### Как исправить / How to fix
    /// Реализовать функцию полностью либо удалить её из библиотечной
    /// поверхности до завершения. Промежуточная реализация недопустима
    /// на ветке `main` per QUALITY_STANDARDS §1 «промежуточный прогресс
    /// живёт в feature-branch, не в `main`».
    ///
    /// Implement the function fully or remove it from the library
    /// surface until completion. Intermediate implementations are
    /// disallowed on `main` per QUALITY_STANDARDS §1 — "intermediate
    /// progress lives in a feature-branch, not in `main`".
    pub NO_TODO_IN_LIB,
    Warn,
    "use of `todo!()` macro in lib code (production must be complete on `main`; panic vector)"
}

pub struct NoTodoInLib;

impl_lint_pass!(NoTodoInLib => [NO_TODO_IN_LIB]);

impl<'tcx> LateLintPass<'tcx> for NoTodoInLib {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let Some(macro_call) = root_macro_call_first_node(cx, expr) else {
            return;
        };
        let Some(diag_name) = cx.tcx.get_diagnostic_name(macro_call.def_id) else {
            return;
        };
        if diag_name != sym::todo_macro {
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
            NO_TODO_IN_LIB,
            macro_call.span,
            "`todo!()` is not allowed in library code (QUALITY_STANDARDS §1 §3: production must be complete on `main`)",
            None,
            "implement the function fully or remove it from the library surface until completion; \
             intermediate implementations belong in a feature-branch, not on `main`; \
             see QUALITY_STANDARDS §1 «промежуточный прогресс живёт в feature-branch» + ADR-015 §Decision 5 criterion 5",
        );
    }
}
