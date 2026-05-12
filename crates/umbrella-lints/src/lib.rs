//! Кастомные dylint-правила Umbrella Protocol.
//! Custom dylint lints for Umbrella Protocol.
//!
//! Этап 9 — Hardening, блок 9.8c (process maturity quality gates) — 3 правила.
//! Этап 11 — пост-1.0 операционный трек, блок 11.8 (расширение anti-panic
//! правил workspace-wide для closure ADR-015 §Решение 5 критерий 5 «zero
//! panics в lib code») — +5 правил, итого 8.
//! Stage 9 — Hardening, block 9.8c (process maturity quality gates) — 3 rules.
//! Stage 11 — post-1.0 operational track, block 11.8 (expansion of
//! anti-panic rules workspace-wide to close ADR-015 §Decision 5
//! criterion 5 "zero panics in lib code") — +5 rules, 8 total.
//!
//! Правила / Rules:
//! 1. [`NO_EQ_FOR_SECRET`] — запрещает `==`/`!=` для типов, реализующих
//!    `Zeroize` (постулат 4 «приватность превыше всего» — защита от
//!    timing-атак).
//!    Forbids `==`/`!=` on types that implement `Zeroize` (postulate 4
//!    "privacy above all" — defence against timing attacks).
//! 2. [`NO_UNWRAP_IN_LIB`] — запрещает `.unwrap()`/`.expect()` в файлах
//!    `src/**/*.rs` (постулат 3 «production-grade без panic»).
//!    Forbids `.unwrap()`/`.expect()` in `src/**/*.rs` files (postulate 3
//!    "production-grade without panics").
//! 3. [`REQUIRE_DUAL_DOC`] — требует наличия и кириллицы, и латиницы в
//!    docstring публичных API (постулат 14 «двойные комментарии RU+EN»).
//!    Requires both Cyrillic and Latin characters in the docstring of
//!    public APIs (postulate 14 "dual RU+EN comments").
//! 4. [`no_panic_in_lib::NO_PANIC_IN_LIB`] — запрещает макрос `panic!()`
//!    в библиотечном коде (ADR-015 §Решение 5 критерий 5).
//!    Forbids the `panic!()` macro in library code.
//! 5. [`no_assert_in_lib::NO_ASSERT_IN_LIB`] — запрещает макрос
//!    `assert!()` в библиотечном коде.
//!    Forbids the `assert!()` macro in library code.
//! 6. [`no_unreachable_in_lib::NO_UNREACHABLE_IN_LIB`] — запрещает макрос
//!    `unreachable!()` в библиотечном коде.
//!    Forbids the `unreachable!()` macro in library code.
//! 7. [`no_todo_in_lib::NO_TODO_IN_LIB`] — запрещает макрос `todo!()` в
//!    библиотечном коде.
//!    Forbids the `todo!()` macro in library code.
//! 8. [`no_unimplemented_in_lib::NO_UNIMPLEMENTED_IN_LIB`] — запрещает
//!    макрос `unimplemented!()` в библиотечном коде.
//!    Forbids the `unimplemented!()` macro in library code.
//!
//! Документация — `docs/audits/dylint-rules.md`.
//! Documentation — `docs/audits/dylint-rules.md`.

#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

mod no_assert_in_lib;
mod no_panic_in_lib;
mod no_todo_in_lib;
mod no_unimplemented_in_lib;
mod no_unreachable_in_lib;

use clippy_utils::diagnostics::{span_lint_and_help, span_lint_and_note};
use clippy_utils::paths::{PathNS, lookup_path_str};
use clippy_utils::ty::implements_trait;
use rustc_hir::def_id::DefId;
use rustc_hir::{BinOpKind, Expr, ExprKind, Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass, LintStore};
use rustc_middle::ty::TyCtxt;
use rustc_session::config::CrateType;
use rustc_session::{Session, declare_lint, impl_lint_pass};

// ----------------------------------------------------------------------------
// Регистрация lints в драйвере dylint.
// dylint driver lint registration.
// ----------------------------------------------------------------------------

dylint_linting::dylint_library!();

/// Точка входа dylint — регистрирует все восемь кастомных lint'ов
/// (3 базовых из Этапа 9 блока 9.8c + 5 anti-panic из Этапа 11 блока
/// 11.8).
/// dylint entry point — registers all eight custom lints (3 from Stage 9
/// block 9.8c + 5 anti-panic rules from Stage 11 block 11.8).
#[expect(clippy::no_mangle_with_rust_abi, reason = "dylint contract")]
#[unsafe(no_mangle)]
pub fn register_lints(_sess: &Session, lint_store: &mut LintStore) {
    lint_store.register_lints(&[
        NO_EQ_FOR_SECRET,
        NO_UNWRAP_IN_LIB,
        REQUIRE_DUAL_DOC,
        no_panic_in_lib::NO_PANIC_IN_LIB,
        no_assert_in_lib::NO_ASSERT_IN_LIB,
        no_unreachable_in_lib::NO_UNREACHABLE_IN_LIB,
        no_todo_in_lib::NO_TODO_IN_LIB,
        no_unimplemented_in_lib::NO_UNIMPLEMENTED_IN_LIB,
    ]);
    lint_store.register_late_pass(|_| Box::new(NoEqForSecret::default()));
    lint_store.register_late_pass(|_| Box::new(NoUnwrapInLib));
    lint_store.register_late_pass(|_| Box::new(RequireDualDoc));
    lint_store.register_late_pass(|_| Box::new(no_panic_in_lib::NoPanicInLib));
    lint_store.register_late_pass(|_| Box::new(no_assert_in_lib::NoAssertInLib));
    lint_store.register_late_pass(|_| Box::new(no_unreachable_in_lib::NoUnreachableInLib));
    lint_store.register_late_pass(|_| Box::new(no_todo_in_lib::NoTodoInLib));
    lint_store.register_late_pass(|_| Box::new(no_unimplemented_in_lib::NoUnimplementedInLib));
}

// ----------------------------------------------------------------------------
// Lint 1 — `no_eq_for_secret`.
// ----------------------------------------------------------------------------

declare_lint! {
    /// ### Что делает / What it does
    /// Запрещает операторы `==` и `!=` для типов, реализующих
    /// [`zeroize::ZeroizeOnDrop`]. Этот трейт — маркер реального
    /// секретного материала (приватные ключи, общие секреты, мнемоника),
    /// а не любых zeroize-aware типов вроде `String`/`Vec<u8>`.
    ///
    /// Forbids the `==` and `!=` operators on types that implement
    /// [`zeroize::ZeroizeOnDrop`]. The trait is a marker for genuine
    /// secret material (private keys, shared secrets, mnemonics), not
    /// arbitrary zeroize-aware types like `String`/`Vec<u8>`.
    ///
    /// ### Почему это плохо / Why is this bad?
    /// Постулат 4 — «приватность превыше всего». Время выполнения `==`
    /// зависит от данных (early-exit на первом несовпадающем байте),
    /// что позволяет атакующему восстановить секрет по микро-секундным
    /// различиям в задержке.
    ///
    /// Postulate 4 — "privacy above all". The execution time of `==`
    /// depends on the data (early exit on the first mismatched byte),
    /// allowing an attacker to recover the secret from microsecond-level
    /// timing differences.
    ///
    /// ### Как исправить / How to fix
    /// Использовать [`subtle::ConstantTimeEq`] или [`subtle::CtOption`]:
    /// ```text
    /// use subtle::ConstantTimeEq;
    /// if secret_a.ct_eq(&secret_b).into() { ... }
    /// ```
    ///
    /// Use [`subtle::ConstantTimeEq`] or [`subtle::CtOption`]:
    /// ```text
    /// use subtle::ConstantTimeEq;
    /// if secret_a.ct_eq(&secret_b).into() { ... }
    /// ```
    pub NO_EQ_FOR_SECRET,
    Warn,
    "use of `==`/`!=` on a ZeroizeOnDrop-typed value (timing-attack risk)"
}

#[derive(Default)]
pub struct NoEqForSecret {
    /// Кэш `DefId` трейта `zeroize::ZeroizeOnDrop` — резолвится один раз
    /// при первом вызове `check_expr` и переиспользуется до конца
    /// прохода компиляции.
    /// Cached `DefId` for the `zeroize::ZeroizeOnDrop` trait — resolved
    /// once on the first `check_expr` call and reused for the rest of
    /// the compilation pass.
    zeroize_on_drop_trait: Option<Option<DefId>>,
}

impl_lint_pass!(NoEqForSecret => [NO_EQ_FOR_SECRET]);

impl<'tcx> LateLintPass<'tcx> for NoEqForSecret {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let ExprKind::Binary(op, lhs, _rhs) = &expr.kind else {
            return;
        };
        if !matches!(op.node, BinOpKind::Eq | BinOpKind::Ne) {
            return;
        }

        let trait_id = match self.zeroize_on_drop_trait {
            Some(cached) => cached,
            None => {
                let resolved = find_trait_by_path(cx.tcx, "zeroize::ZeroizeOnDrop");
                self.zeroize_on_drop_trait = Some(resolved);
                resolved
            }
        };
        let Some(trait_id) = trait_id else {
            return;
        };

        let lhs_ty = cx.typeck_results().expr_ty_adjusted(lhs).peel_refs();
        if !implements_trait(cx, lhs_ty, trait_id, &[]) {
            return;
        }

        span_lint_and_help(
            cx,
            NO_EQ_FOR_SECRET,
            expr.span,
            "use of `==`/`!=` on a `ZeroizeOnDrop` type may leak the secret via timing",
            None,
            "use `subtle::ConstantTimeEq::ct_eq` for constant-time comparison",
        );
    }
}

/// Ищет `DefId` трейта по полному пути. Использует
/// [`clippy_utils::paths::lookup_path_str`] с пространством имён `Type`,
/// которое корректно резолвит трейты в transitive-зависимостях.
/// Looks up a trait `DefId` by its fully qualified path. Uses
/// [`clippy_utils::paths::lookup_path_str`] with the `Type` namespace,
/// which correctly resolves traits in transitive dependencies.
fn find_trait_by_path(tcx: TyCtxt<'_>, path: &str) -> Option<DefId> {
    lookup_path_str(tcx, PathNS::Type, path).into_iter().next()
}

// ----------------------------------------------------------------------------
// Lint 2 — `no_unwrap_in_lib`.
// ----------------------------------------------------------------------------

declare_lint! {
    /// ### Что делает / What it does
    /// Запрещает вызовы `.unwrap()` и `.expect(_)` в библиотечных
    /// крейтах (тех, чей `crate-type` содержит `lib`/`rlib`/`dylib`/
    /// `cdylib`/`staticlib`). Чисто бинарные крейты (`xtask`,
    /// `examples/*`, `tests/*`) и `#[cfg(test)]`-блоки игнорируются.
    ///
    /// Forbids `.unwrap()` and `.expect(_)` calls in library crates
    /// (those whose `crate-type` includes `lib`/`rlib`/`dylib`/
    /// `cdylib`/`staticlib`). Pure binary crates (`xtask`,
    /// `examples/*`, `tests/*`) and `#[cfg(test)]` blocks are ignored.
    ///
    /// ### Почему это плохо / Why is this bad?
    /// Постулат 3 — «production-grade без panic». Любой `unwrap` в
    /// библиотечной поверхности превращается в panic у клиента; вместо
    /// этого нужен `Result` либо `let-else`.
    ///
    /// Postulate 3 — "production-grade without panics". Any `unwrap` in
    /// the library surface becomes a panic for the client; use `Result`
    /// or `let-else` instead.
    pub NO_UNWRAP_IN_LIB,
    Warn,
    "use of `.unwrap()`/`.expect()` in lib code (panic-on-error in production)"
}

pub struct NoUnwrapInLib;

impl_lint_pass!(NoUnwrapInLib => [NO_UNWRAP_IN_LIB]);

impl<'tcx> LateLintPass<'tcx> for NoUnwrapInLib {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let ExprKind::MethodCall(seg, _recv, _args, _call_span) = &expr.kind else {
            return;
        };
        let method_name = seg.ident.name.as_str();
        if method_name != "unwrap" && method_name != "expect" {
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
            NO_UNWRAP_IN_LIB,
            expr.span,
            format!("`.{method_name}()` is not allowed in library code"),
            None,
            "return a `Result`, use `let ... else { ... }`, or move this expression to a `tests/` module",
        );
    }
}

/// Считает крейт библиотечным, если среди `crate-type` есть хотя бы один
/// из вариантов: `Rlib`, `Lib`, `Dylib`, `Cdylib`, `Staticlib`.
/// Считает чисто бинарным, если есть только `Executable`.
/// Treats a crate as a library if its `crate-type` list contains at least
/// one of `Rlib`, `Lib`, `Dylib`, `Cdylib`, `Staticlib`. Treats it as
/// purely binary if only `Executable` is present.
///
/// `pub(crate)` — переиспользуется модулями `no_panic_in_lib` /
/// `no_assert_in_lib` / `no_unreachable_in_lib` / `no_todo_in_lib` /
/// `no_unimplemented_in_lib` (Этап 11 блок 11.8).
/// `pub(crate)` — reused by the `no_panic_in_lib` /
/// `no_assert_in_lib` / `no_unreachable_in_lib` / `no_todo_in_lib` /
/// `no_unimplemented_in_lib` modules (Stage 11 block 11.8).
pub(crate) fn is_library_crate(cx: &LateContext<'_>) -> bool {
    cx.tcx.crate_types().iter().any(|ct| {
        matches!(
            ct,
            CrateType::Rlib | CrateType::Dylib | CrateType::Cdylib | CrateType::Staticlib
        )
    })
}

// ----------------------------------------------------------------------------
// Lint 3 — `require_dual_doc`.
// ----------------------------------------------------------------------------

declare_lint! {
    /// ### Что делает / What it does
    /// Требует, чтобы docstring публичного элемента содержал как
    /// латинские, так и кириллические символы. Если присутствует
    /// только один алфавит — emit warning.
    ///
    /// Requires the docstring of a public item to contain both Latin
    /// and Cyrillic characters. Emits a warning if only one alphabet
    /// is present.
    ///
    /// Полное отсутствие docstring пропускается — за это отвечает
    /// стандартный `missing_docs` lint.
    ///
    /// A completely missing docstring is skipped — that case is handled
    /// by the standard `missing_docs` lint.
    ///
    /// ### Почему это плохо / Why is this bad?
    /// Постулат 14 — «двойные комментарии RU+EN на каждой публичной
    /// функции». dual-language continuity требует, чтобы документация существовала
    /// в двух языках одновременно.
    ///
    /// Postulate 14 — "dual RU+EN comments on every public function".
    /// dual-language continuity requires documentation to exist in both languages
    /// simultaneously.
    pub REQUIRE_DUAL_DOC,
    Warn,
    "public-API docstring lacks either Cyrillic or Latin characters (dual RU+EN required)"
}

pub struct RequireDualDoc;

impl_lint_pass!(RequireDualDoc => [REQUIRE_DUAL_DOC]);

impl<'tcx> LateLintPass<'tcx> for RequireDualDoc {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        // Скрытые элементы (`#[doc(hidden)]`), макро-генерации и `extern crate`
        // не подпадают под правило публичного API.
        // Hidden items (`#[doc(hidden)]`), macro generations, and `extern crate`
        // are out of scope of the public-API rule.
        if matches!(
            item.kind,
            ItemKind::ExternCrate(..) | ItemKind::Use(..) | ItemKind::ForeignMod { .. }
        ) {
            return;
        }
        if item.span.from_expansion() {
            return;
        }

        let def_id = item.owner_id.def_id;
        let visibility = cx.tcx.visibility(def_id);
        if !visibility.is_public() {
            return;
        }

        let attrs = cx.tcx.hir_attrs(item.hir_id());
        let mut combined = String::new();
        for attr in attrs {
            if let Some(doc) = attr.doc_str() {
                combined.push_str(doc.as_str());
                combined.push('\n');
            }
        }
        let trimmed = combined.trim();
        if trimmed.is_empty() {
            // Нет docstring вовсе — `missing_docs` lint обработает.
            // No docstring at all — `missing_docs` lint handles this case.
            return;
        }

        let has_cyrillic = trimmed.chars().any(is_cyrillic);
        let has_latin = trimmed.chars().any(is_latin_letter);

        if has_cyrillic && has_latin {
            return;
        }

        let missing = if has_latin { "Cyrillic" } else { "Latin" };
        span_lint_and_help(
            cx,
            REQUIRE_DUAL_DOC,
            item.span,
            format!("public docstring is missing {missing} text — RU+EN required"),
            None,
            "add a paragraph in the missing language; see постулат 14 in docs/WORKING_RULES.md",
        );
    }
}

/// Кириллица: основной диапазон Юникода `U+0400..=U+04FF` плюс
/// дополнительный `U+0500..=U+052F` (расширенная кириллица).
/// Cyrillic: the main Unicode range `U+0400..=U+04FF` plus the
/// supplementary `U+0500..=U+052F` (Cyrillic Supplement).
fn is_cyrillic(ch: char) -> bool {
    matches!(ch, '\u{0400}'..='\u{04FF}' | '\u{0500}'..='\u{052F}')
}

/// Базовая латиница `A-Z` / `a-z` без диакритики (достаточно для проверки
/// английского текста в docstring'е).
/// Basic Latin `A-Z` / `a-z` without diacritics (sufficient to detect
/// English text in a docstring).
fn is_latin_letter(ch: char) -> bool {
    ch.is_ascii_alphabetic()
}

// ----------------------------------------------------------------------------
// UI-тесты — компилируются и проверяют, что lint выдаёт ожидаемый stderr.
// UI tests — compile examples and verify the lint emits the expected stderr.
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    /// Запускает standalone ui-сценарии из каталога `ui/`. `dylint_testing`
    /// перебирает каждый `.rs`-файл без dev-dependencies (для случаев, где
    /// внешние крейты не нужны). Bless: `BLESS=1 cargo test`.
    /// Runs the standalone UI scenarios from the `ui/` directory.
    /// `dylint_testing` iterates over each `.rs` file without
    /// dev-dependencies (for cases that do not need external crates).
    /// Bless via `BLESS=1 cargo test`.
    #[test]
    fn ui() {
        dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
    }

    /// Запускает example-сценарии из `examples/`, которым нужны dev-deps
    /// (`zeroize` для `no_eq_for_secret`). `ui_test_examples` собирает
    /// каждый `[[example]]` с полным dependency graph и сверяет stderr.
    /// Runs the example scenarios from `examples/` that need dev-deps
    /// (`zeroize` for `no_eq_for_secret`). `ui_test_examples` builds each
    /// `[[example]]` with the full dependency graph and compares stderr.
    ///
    /// **Игнорируется** до фикса бага в `dylint_testing` 5.0.0: путь к
    /// `--extern zeroize=...` усекается на первом пробеле, и крейт с
    /// рабочим каталогом `.../Umbrella Protocol/...` не разрешается.
    /// Smoke-проверка правила выполняется через `cargo dylint --workspace`
    /// на основном workspace (там есть реальные `Zeroize`-типы), а
    /// автоматический UI-тест включится после bump до dylint_testing > 5.0.0.
    /// **Ignored** until a `dylint_testing` 5.0.0 bug is fixed: the
    /// `--extern zeroize=...` path is truncated at the first whitespace,
    /// which breaks resolution for crates whose working directory is
    /// `.../Umbrella Protocol/...`. The rule is still smoke-tested via
    /// `cargo dylint --workspace` on the main workspace (which contains
    /// real `Zeroize` types); the automated UI test is enabled after
    /// bumping to dylint_testing > 5.0.0.
    #[test]
    #[ignore = "dylint_testing 5.0.0 truncates --extern path on whitespace; tracked in docs/audits/production-readiness-2026-05-09/residual-risks.md (block 9.8c)"]
    fn ui_examples() {
        dylint_testing::ui_test_examples(env!("CARGO_PKG_NAME"));
    }
}
