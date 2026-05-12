//! NIST FIPS 203/204/205 Known Answer Test (KAT) vector loader.
//! NIST FIPS 203/204/205 Known Answer Test (KAT) vector loader.
//!
//! Этот модуль предоставляет infrastructure для загрузки и парсинга KAT-векторов
//! NIST CSRC ACVP в JSON-формате. Векторы используются в `umbrella-pq` тестах
//! для cross-test против reference implementation NIST.
//!
//! This module provides infrastructure for loading and parsing NIST CSRC ACVP
//! KAT vectors in JSON format. The vectors are used in `umbrella-pq` tests for
//! cross-testing against the NIST reference implementation.
//!
//! # Wire-format
//!
//! Каждый вектор — JSON-объект с hex-encoded полями:
//!
//! ```json
//! {
//!   "vector_id": 0,
//!   "seed_hex": "deadbeef...",
//!   "expected_pk_hex": "...",
//!   "expected_sk_hex": "...",
//!   "message_hex": "0123",
//!   "context_hex": "",
//!   "expected_signature_hex": "...",
//!   "expected_ciphertext_hex": "...",
//!   "expected_shared_secret_hex": "..."
//! }
//! ```
//!
//! Поля `message`/`context`/`signature`/`ciphertext`/`shared_secret` опциональны
//! — присутствуют только для применимых тестовых случаев (sign/verify, encaps/decaps).
//!
//! Fields `message`/`context`/`signature`/`ciphertext`/`shared_secret` are
//! optional — present only for applicable test cases (sign/verify, encaps/decaps).
//!
//! # Файлы
//!
//! - `data/nist-fips-203-ml-kem-768.json` — ML-KEM-768 KAT.
//! - `data/nist-fips-204-ml-dsa-65.json` — ML-DSA-65 KAT.
//! - `data/nist-fips-205-slh-dsa-128f.json` — SLH-DSA-SHA2-128f-simple KAT.
//! - `data/xwing-draft-connolly.json` — X-Wing draft-connolly Appendix B vectors.
//!
//! Все файлы read-only. Updates через ADR-поправку + checksum update в
//! `CHECKSUMS.txt`.
//!
//! All files are read-only. Updates via ADR amendment + checksum update in
//! `CHECKSUMS.txt`.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Один KAT-вектор в нашем универсальном формате.
/// A single KAT vector in our universal format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NistKatVector {
    /// Идентификатор вектора в исходном источнике.
    /// Vector identifier in the source.
    pub vector_id: u32,

    /// Seed для deterministic keygen (hex-encoded).
    /// Seed for deterministic keygen (hex-encoded).
    pub seed_hex: String,

    /// Ожидаемый public key (hex). Опциональный — некоторые vectors только
    /// проверяют encaps/sign не предоставляя ожидаемый pk.
    /// Expected public key (hex). Optional — some vectors only check
    /// encaps/sign without providing the expected pk.
    pub expected_pk_hex: Option<String>,

    /// Ожидаемый secret key (hex). Опциональный.
    /// Expected secret key (hex). Optional.
    pub expected_sk_hex: Option<String>,

    /// Message для sign/encaps (hex). Опциональный.
    /// Message for sign/encaps (hex). Optional.
    pub message_hex: Option<String>,

    /// Domain separation context (hex). Опциональный (пустой при отсутствии).
    /// Domain separation context (hex). Optional (empty when absent).
    pub context_hex: Option<String>,

    /// Ожидаемая signature (hex). Опциональный.
    /// Expected signature (hex). Optional.
    pub expected_signature_hex: Option<String>,

    /// Ожидаемый ciphertext (hex). Опциональный.
    /// Expected ciphertext (hex). Optional.
    pub expected_ciphertext_hex: Option<String>,

    /// Ожидаемый shared secret (hex). Опциональный.
    /// Expected shared secret (hex). Optional.
    pub expected_shared_secret_hex: Option<String>,

    /// Дополнительный seed для encaps (hex; для KEM `encapsulate_derand`).
    /// Additional seed for encaps (hex; for KEM `encapsulate_derand`).
    pub encaps_seed_hex: Option<String>,

    /// Описание/комментарий вектора (опциональный, человекочитаемый).
    /// Vector description/comment (optional, human-readable).
    pub note: Option<String>,
}

/// Файл с массивом KAT-векторов.
/// File containing an array of KAT vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NistKatFile {
    /// Алгоритм (`ml-kem-768`, `ml-dsa-65`, `slh-dsa-128f`, `x-wing`).
    /// Algorithm (`ml-kem-768`, `ml-dsa-65`, `slh-dsa-128f`, `x-wing`).
    pub algorithm: String,

    /// Источник (URL или upstream reference).
    /// Source (URL or upstream reference).
    pub source: String,

    /// Список векторов.
    /// Vector list.
    pub vectors: Vec<NistKatVector>,
}

/// Ошибки парсинга/загрузки KAT файлов.
/// KAT file parsing/loading errors.
#[derive(Debug, Error)]
pub enum NistKatError {
    /// Ошибка чтения файла с диска.
    /// File read error.
    #[error("failed to read KAT file: {0}")]
    Io(#[from] std::io::Error),

    /// Ошибка парсинга JSON.
    /// JSON parse error.
    #[error("failed to parse KAT JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Невалидный hex в поле.
    /// Invalid hex in a field.
    #[error("invalid hex in field {field}: {source}")]
    Hex {
        /// Имя поля где произошла ошибка.
        /// Field name where the error occurred.
        field: String,
        /// Underlying hex parse error.
        /// Underlying hex parse error.
        source: hex::FromHexError,
    },
}

/// Загрузить KAT файл из абсолютного пути.
/// Load a KAT file from an absolute path.
pub fn load_nist_kat_file(path: &Path) -> Result<NistKatFile, NistKatError> {
    let bytes = fs::read(path)?;
    let parsed: NistKatFile = serde_json::from_slice(&bytes)?;
    Ok(parsed)
}

/// Декодировать hex поле; возвращает `NistKatError::Hex` с именем поля при ошибке.
/// Decode a hex field; returns `NistKatError::Hex` with the field name on error.
pub fn decode_hex(value: &str, field_name: &str) -> Result<Vec<u8>, NistKatError> {
    hex::decode(value).map_err(|source| NistKatError::Hex {
        field: field_name.to_string(),
        source,
    })
}

/// Helper для декодирования optional hex поля.
/// Helper to decode an optional hex field.
pub fn decode_hex_opt(
    value: Option<&String>,
    field_name: &str,
) -> Result<Option<Vec<u8>>, NistKatError> {
    value.map(|v| decode_hex(v, field_name)).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Базовая структура KAT файла парсится через serde_json.
    /// Basic KAT file structure parses via serde_json.
    #[test]
    fn parse_minimal_kat_file() {
        let json = r#"{
            "algorithm": "ml-kem-768",
            "source": "internal-stability-test",
            "vectors": [
                {
                    "vector_id": 0,
                    "seed_hex": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                    "expected_pk_hex": null,
                    "expected_sk_hex": null,
                    "message_hex": null,
                    "context_hex": null,
                    "expected_signature_hex": null,
                    "expected_ciphertext_hex": null,
                    "expected_shared_secret_hex": null,
                    "encaps_seed_hex": null,
                    "note": "minimal vector"
                }
            ]
        }"#;
        let file: NistKatFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.algorithm, "ml-kem-768");
        assert_eq!(file.vectors.len(), 1);
        assert_eq!(file.vectors[0].vector_id, 0);
        assert_eq!(file.vectors[0].seed_hex.len(), 128);
    }

    /// Hex decoding работает на правильных hex и фейлится на невалидных.
    /// Hex decoding works on valid hex and fails on invalid.
    #[test]
    fn decode_hex_valid_and_invalid() {
        assert_eq!(
            decode_hex("deadbeef", "test").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(decode_hex("not-hex!", "test").is_err());
    }

    /// `decode_hex_opt` корректно обрабатывает None и Some.
    /// `decode_hex_opt` correctly handles None and Some.
    #[test]
    fn decode_hex_opt_handles_none() {
        assert_eq!(decode_hex_opt(None, "test").unwrap(), None);
        let some_hex = "00ff".to_string();
        assert_eq!(
            decode_hex_opt(Some(&some_hex), "test").unwrap(),
            Some(vec![0x00, 0xff])
        );
    }

    /// При наличии stability KAT файлов в data/ — они грузятся.
    /// If stability KAT files exist in data/ — they load.
    #[test]
    fn load_stability_kat_files_if_present() {
        let crate_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let data_dir = crate_root.join("data");
        if !data_dir.exists() {
            // data/ optional — KAT может быть deferred в отдельный коммит.
            return;
        }
        for entry_name in [
            "stability-ml-kem-768.json",
            "stability-x-wing.json",
            "stability-ml-dsa-65.json",
            "stability-slh-dsa-128f.json",
        ] {
            let path = data_dir.join(entry_name);
            if path.exists() {
                let file = load_nist_kat_file(&path)
                    .unwrap_or_else(|e| panic!("load {entry_name} failed: {e:?}"));
                assert!(
                    !file.vectors.is_empty(),
                    "{entry_name} must have at least 1 vector"
                );
            }
        }
    }
}
