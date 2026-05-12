//! CLI demo: round-trip recovery — milestone Этапа 1.
//! CLI demo: round-trip recovery — Stage 1 milestone.
//!
//! Запуск / Run:
//!   cargo run --example recovery_demo -p umbrella-identity -- generate
//!   cargo run --example recovery_demo -p umbrella-identity -- restore "слово1 слово2 ... слово24"
//!
//! Проверка инварианта Этапа 1: восстановление из 24 слов даёт идентичный
//! identity_pubkey тому, что был при первоначальной генерации.
//! Stage 1 invariant check: restoring from 24 words yields an identity_pubkey
//! identical to the one produced at initial generation.

use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use rand_core::OsRng;

use umbrella_identity::{
    Clock, IdentityKey, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};

const ACCOUNT: u32 = 0;

fn print_usage(program: &str) {
    eprintln!(
        "Usage:\n  {program} generate\n  {program} restore \"<24 words>\"\n  {program} round-trip"
    );
}

fn cmd_generate() -> ExitCode {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let mnemonic = seed.to_mnemonic();
    let store = match InMemoryKeyStore::open(seed, ACCOUNT, Arc::new(SystemClock)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to open keystore: {e}");
            return ExitCode::FAILURE;
        }
    };
    let pubkey = store.identity_public();
    println!("=== Umbrella Protocol identity generation ===");
    println!("mnemonic (24 words): {}", mnemonic.as_str());
    println!("identity pubkey hex: {}", to_hex(&pubkey.to_bytes()));
    println!("account index      : {}", store.account());
    println!();
    println!("Сохраните мнемонику в безопасном месте.");
    println!("Для проверки восстановления:");
    println!(
        "  cargo run --example recovery_demo -p umbrella-identity -- restore \"{}\"",
        mnemonic.as_str()
    );
    ExitCode::SUCCESS
}

fn cmd_restore(phrase: &str) -> ExitCode {
    let seed = match IdentitySeed::from_mnemonic(phrase, MnemonicLanguage::English) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: invalid mnemonic: {e}");
            return ExitCode::FAILURE;
        }
    };
    let identity = match IdentityKey::derive(&seed, ACCOUNT) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: failed to derive identity: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("=== Umbrella Protocol identity restored ===");
    println!(
        "identity pubkey hex: {}",
        to_hex(&identity.public().to_bytes())
    );
    println!("account index      : {ACCOUNT}");
    ExitCode::SUCCESS
}

fn cmd_round_trip() -> ExitCode {
    let mut rng = OsRng;
    let original_seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let mnemonic = original_seed.to_mnemonic();

    let original_identity = match IdentityKey::derive(&original_seed, ACCOUNT) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: derive original identity failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let original_pubkey = original_identity.public().to_bytes();

    let restored_seed =
        match IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: restore from mnemonic failed: {e}");
                return ExitCode::FAILURE;
            }
        };
    let restored_identity = match IdentityKey::derive(&restored_seed, ACCOUNT) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: derive restored identity failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let restored_pubkey = restored_identity.public().to_bytes();

    let now = SystemClock.now_unix_secs();
    let clock = Arc::new(SystemClock);

    let original_store =
        InMemoryKeyStore::open(original_seed, ACCOUNT, clock.clone() as Arc<dyn Clock>).unwrap();
    let restored_store =
        InMemoryKeyStore::open(restored_seed, ACCOUNT, clock as Arc<dyn Clock>).unwrap();

    // Регистрируем устройство 0 в обоих keystore — публичный device-key должен совпадать.
    // Register device 0 in both keystores — public device key must match.
    let original_att = original_store.add_device(0, Some(86_400)).unwrap();
    let restored_att = restored_store.add_device(0, Some(86_400)).unwrap();
    let original_dev_pub = original_store.device_public(0).unwrap().to_bytes();
    let restored_dev_pub = restored_store.device_public(0).unwrap().to_bytes();

    println!("=== Round-trip recovery test ===");
    println!("mnemonic            : {}", mnemonic.as_str());
    println!("original identity   : {}", to_hex(&original_pubkey));
    println!("restored identity   : {}", to_hex(&restored_pubkey));
    println!(
        "identity match      : {}",
        original_pubkey == restored_pubkey
    );
    println!("original device 0   : {}", to_hex(&original_dev_pub));
    println!("restored device 0   : {}", to_hex(&restored_dev_pub));
    println!(
        "device 0 match      : {}",
        original_dev_pub == restored_dev_pub
    );
    println!(
        "att verify @ now    : {}",
        original_att
            .verify(&restored_store.identity_public(), now)
            .is_ok()
    );
    let _ = restored_att;

    if original_pubkey == restored_pubkey && original_dev_pub == restored_dev_pub {
        println!();
        println!("MILESTONE OK: 24 слова → восстановленный identity_pubkey идентичен оригиналу.");
        ExitCode::SUCCESS
    } else {
        eprintln!();
        eprintln!("MILESTONE FAIL: round-trip не дал идентичный pubkey.");
        ExitCode::FAILURE
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to String never fails");
    }
    s
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let program = args.first().map(String::as_str).unwrap_or("recovery_demo");
    if args.len() < 2 {
        print_usage(program);
        return ExitCode::FAILURE;
    }
    match args[1].as_str() {
        "generate" => cmd_generate(),
        "restore" => {
            if args.len() < 3 {
                eprintln!("error: 'restore' requires the mnemonic phrase as a single argument");
                print_usage(program);
                return ExitCode::FAILURE;
            }
            cmd_restore(&args[2])
        }
        "round-trip" => cmd_round_trip(),
        other => {
            eprintln!("error: unknown command: {other}");
            print_usage(program);
            ExitCode::FAILURE
        }
    }
}
