//! Хост-крейт для интеграционных и interop тестов; настоящие тесты в `tests/`.
//! Host crate for integration and interop tests; actual tests live in `tests/`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dudect;

/// Заглушка-маркер сборки. Build marker placeholder.
pub const BUILD_MARKER: &str = "umbrella-tests stage-0 skeleton";
