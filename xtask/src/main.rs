//! Cargo workspace automation: SBOM generation, Sigstore signing, future build helpers.
//! Автоматизация workspace: генерация SBOM, подпись Sigstore, будущие хелперы сборки.
//!
//! ## Команды / Commands
//!
//! `xtask sbom` — сгенерировать `docs/audits/sbom.json` через `cargo sbom`
//! (CycloneDX 1.6 JSON, весь workspace).
//! Generates `docs/audits/sbom.json` via `cargo sbom` (CycloneDX 1.6 JSON,
//! full workspace).
//!
//! `xtask sign <PATH>` — подписать файл `<PATH>` через `cosign sign-blob`
//! с приватным ключом `cosign.key` (требует переменную среды
//! `COSIGN_PASSWORD` либо интерактивный prompt). Сигнатура пишется в
//! `<PATH>.sig`.
//! Signs `<PATH>` via `cosign sign-blob` using the `cosign.key` private key
//! (requires `COSIGN_PASSWORD` env var or interactive prompt). Signature
//! is written to `<PATH>.sig`.
//!
//! `xtask verify <PATH>` — проверить подпись через `cosign verify-blob`
//! с публичным ключом `cosign.pub`. Sig читается из `<PATH>.sig`.
//! Verifies signature via `cosign verify-blob` using the `cosign.pub`
//! public key. Signature is read from `<PATH>.sig`.
//!
//! `xtask help` — печатает usage / prints usage.
//!
//! ## Производственные предусловия / Production prerequisites
//!
//! Установка инструментов / Tooling install:
//! `cargo install cargo-sbom` (<https://github.com/psastras/sbom-rs>);
//! `cosign` CLI v3.0.0+ (<https://github.com/sigstore/cosign>).
//!
//! Файлы ключей / Key files: `cosign.key` (приватный, в `.gitignore`) и
//! `cosign.pub` (публичный, коммитится в репо). Setup инструкции —
//! `docs/audits/sigstore-signing.md`.

use anyhow::{bail, Context, Result};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const USAGE: &str = "\
xtask — Umbrella Protocol workspace automation

USAGE:
    cargo xtask <COMMAND> [ARGS]

COMMANDS:
    sbom              Generate CycloneDX SBOM in docs/audits/sbom.json
    sign <PATH>       Sign file with cosign.key, output <PATH>.sig
    verify <PATH>     Verify <PATH> against <PATH>.sig with cosign.pub
    help              Print this help

EXAMPLES:
    cargo xtask sbom
    cargo xtask sign target/release/libumbrella_ffi.dylib
    cargo xtask verify target/release/libumbrella_ffi.dylib

DOCS:
    docs/audits/reproducible-builds.md   Deterministic build flags + verification.
    docs/audits/sigstore-signing.md      Cosign keypair setup + signing workflow.
";

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".to_string());

    match cmd.as_str() {
        "sbom" => cmd_sbom(),
        "sign" => {
            let path = args.next().context("`xtask sign` requires <PATH>")?;
            cmd_sign(&PathBuf::from(path))
        }
        "verify" => {
            let path = args.next().context("`xtask verify` requires <PATH>")?;
            cmd_verify(&PathBuf::from(path))
        }
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print!("{USAGE}");
            bail!("unknown xtask command: {other}");
        }
    }
}

/// Сгенерировать CycloneDX SBOM в `docs/audits/sbom.json`.
/// Generate CycloneDX SBOM at `docs/audits/sbom.json`.
///
/// Использует внешний бинарник `cargo-sbom` (через `cargo sbom`); если он
/// не установлен — выводит инструкцию по установке. Output формат —
/// CycloneDX 1.6 JSON, охват — весь workspace включая dev-dependencies.
///
/// Uses the external `cargo-sbom` binary (via `cargo sbom`); if not
/// installed, prints install instructions. Output format is CycloneDX 1.4
/// JSON, scope is the entire workspace including dev-dependencies.
fn cmd_sbom() -> Result<()> {
    let workspace_root = workspace_root()?;
    let output_path = workspace_root.join("docs").join("audits").join("sbom.json");

    println!("xtask sbom: generating CycloneDX SBOM via `cargo sbom`");
    println!("xtask sbom: output -> {}", output_path.display());

    let status = Command::new("cargo")
        .args(["sbom", "--output-format", "cyclone_dx_json_1_6"])
        .current_dir(&workspace_root)
        .stdout(
            std::fs::File::create(&output_path)
                .with_context(|| format!("create {}", output_path.display()))?,
        )
        .status()
        .context(
            "failed to invoke `cargo sbom`. Install: `cargo install cargo-sbom` \
             (https://github.com/psastras/sbom-rs)",
        )?;

    if !status.success() {
        bail!("`cargo sbom` exited with non-zero status: {status}");
    }

    let bytes = std::fs::metadata(&output_path)
        .with_context(|| format!("stat {}", output_path.display()))?
        .len();
    println!(
        "xtask sbom: wrote {bytes} bytes to {}",
        output_path.display()
    );
    Ok(())
}

/// Подписать `path` через `cosign sign-blob`. Signature пишется в `<path>.sig`.
/// Sign `path` via `cosign sign-blob`. Signature is written to `<path>.sig`.
fn cmd_sign(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("file not found: {}", path.display());
    }
    let workspace_root = workspace_root()?;
    let key = workspace_root.join("cosign.key");
    if !key.exists() {
        bail!(
            "private key not found: {}\n\
             Run `cosign generate-key-pair` in workspace root to create it. \
             See docs/audits/sigstore-signing.md.",
            key.display()
        );
    }
    let sig_path = path.with_extension(
        path.extension()
            .map(|e| {
                let mut s = e.to_os_string();
                s.push(".sig");
                s
            })
            .unwrap_or_else(|| std::ffi::OsString::from("sig")),
    );

    println!(
        "xtask sign: signing {} -> {}",
        path.display(),
        sig_path.display()
    );

    let status = Command::new("cosign")
        .args(["sign-blob", "--yes", "--key"])
        .arg(&key)
        .arg("--output-signature")
        .arg(&sig_path)
        .arg(path)
        .status()
        .context(
            "failed to invoke `cosign`. Install: see https://docs.sigstore.dev/cosign/installation",
        )?;

    if !status.success() {
        bail!("`cosign sign-blob` exited with non-zero status: {status}");
    }
    println!("xtask sign: signature written to {}", sig_path.display());
    Ok(())
}

/// Проверить подпись через `cosign verify-blob`. Sig читается из `<path>.sig`.
/// Verify signature via `cosign verify-blob`. Signature is read from `<path>.sig`.
fn cmd_verify(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("file not found: {}", path.display());
    }
    let workspace_root = workspace_root()?;
    let pub_key = workspace_root.join("cosign.pub");
    if !pub_key.exists() {
        bail!(
            "public key not found: {}\n\
             See docs/audits/sigstore-signing.md for setup.",
            pub_key.display()
        );
    }
    let sig_path = path.with_extension(
        path.extension()
            .map(|e| {
                let mut s = e.to_os_string();
                s.push(".sig");
                s
            })
            .unwrap_or_else(|| std::ffi::OsString::from("sig")),
    );
    if !sig_path.exists() {
        bail!("signature not found: {}", sig_path.display());
    }

    println!(
        "xtask verify: {} against {}",
        path.display(),
        sig_path.display()
    );

    let status = Command::new("cosign")
        .args(["verify-blob", "--key"])
        .arg(&pub_key)
        .arg("--signature")
        .arg(&sig_path)
        .arg(path)
        .status()
        .context(
            "failed to invoke `cosign`. Install: https://docs.sigstore.dev/cosign/installation",
        )?;

    if !status.success() {
        bail!("`cosign verify-blob` failed — signature does not match");
    }
    println!("xtask verify: OK");
    Ok(())
}

/// Найти корень workspace (директория с верхним `Cargo.toml` workspace).
/// Locate workspace root (directory containing the top-level workspace `Cargo.toml`).
fn workspace_root() -> Result<PathBuf> {
    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR is not set")?;
    let xtask_dir = PathBuf::from(manifest_dir);
    let root = xtask_dir
        .parent()
        .with_context(|| format!("xtask manifest dir has no parent: {}", xtask_dir.display()))?
        .to_path_buf();
    Ok(root)
}
