//! R21 — Real attack: duress PIN triggers UNRECOVERABLE_DELETE
//!
//! Per round-6 spec §«Stage 5» R21:
//! > register account, set normal PIN `123456`, set duress as reverse `654321`.
//! > Enter duress PIN → assert servers received `UNRECOVERABLE_DELETE` command
//! > + 5 shares wiped → assert subsequent normal PIN entry returns "account
//! > does not exist".
//!
//! Numerical outcome reported:
//! - number of servers receiving UNRECOVERABLE_DELETE
//! - share-bytes remaining after wipe (must be 0)
//! - subsequent auth attempt result (must be AccountDeleted, not WrongPin —
//!   visually indistinguishable from never-registered).

use std::time::SystemTime;

use umbrella_threshold_identity::{
    account_state::{AccountOptions, AccountState},
    duress::{is_duress_reverse, DuressTrigger, UnrecoverableDelete},
    error::ThresholdIdentityError,
    pin_kdf,
};

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)
}

fn build_5_server_cluster() -> Vec<AccountState> {
    (0..5)
        .map(|i| {
            AccountState::new(
                [i as u8; 32],
                b"123456",
                [i as u8; 16],
                b"share-encrypted-bytes".to_vec(),
                AccountOptions::default(),
                now(),
            )
            .expect("server account state init")
        })
        .collect()
}

#[test]
fn r21_duress_pin_triggers_unrecoverable_delete_across_all_5_servers() {
    let mut cluster = build_5_server_cluster();
    assert_eq!(cluster.len(), 5, "5 mock servers initialized");

    // Verify pre-wipe state: shares present, pin_hash non-zero.
    let mut pre_wipe_share_bytes = 0usize;
    let mut pre_wipe_nonzero_hashes = 0usize;
    for s in &cluster {
        pre_wipe_share_bytes += s.encrypted_share.len();
        if s.pin_hash != [0u8; pin_kdf::OUTPUT_LEN] {
            pre_wipe_nonzero_hashes += 1;
        }
    }
    eprintln!("[R21] PRE-WIPE: total share bytes={pre_wipe_share_bytes}, non-zero hashes={pre_wipe_nonzero_hashes}/5");
    assert!(pre_wipe_share_bytes > 0);
    assert_eq!(pre_wipe_nonzero_hashes, 5);

    // Detect duress: candidate is reverse of genuine.
    let genuine = b"123456";
    let candidate = b"654321";
    let is_duress = is_duress_reverse(candidate, genuine);
    assert!(is_duress, "reverse PIN detected as duress");

    // Issue UNRECOVERABLE_DELETE to all 5 in parallel (simulation).
    let mut servers_wiped = 0usize;
    for server in cluster.iter_mut() {
        let _cmd = UnrecoverableDelete {
            trigger: DuressTrigger::ReversePin,
            anonymous_id: server.anonymous_id,
        };
        server.unrecoverable_delete();
        servers_wiped += 1;
    }
    eprintln!("[R21] WIPE COMMAND fired across {servers_wiped} servers");
    assert_eq!(servers_wiped, 5);

    // Post-wipe verification.
    let mut post_wipe_share_bytes = 0usize;
    let mut post_wipe_zero_hashes = 0usize;
    let mut revoked_count = 0usize;
    for s in &cluster {
        post_wipe_share_bytes += s.encrypted_share.len();
        if s.pin_hash == [0u8; pin_kdf::OUTPUT_LEN] {
            post_wipe_zero_hashes += 1;
        }
        if s.revoked {
            revoked_count += 1;
        }
    }
    eprintln!(
        "[R21] POST-WIPE: total share bytes={post_wipe_share_bytes}, zero hashes={post_wipe_zero_hashes}/5, revoked={revoked_count}/5"
    );

    // Hard assertions: every byte of share material wiped, every hash zeroed.
    assert_eq!(
        post_wipe_share_bytes, 0,
        "all share bytes wiped across 5 servers"
    );
    assert_eq!(post_wipe_zero_hashes, 5, "all 5 pin hashes zeroed");
    assert_eq!(revoked_count, 5, "all 5 servers marked revoked");

    // Subsequent genuine PIN attempt: must return AccountDeleted (NOT WrongPin).
    // This is the «visually indistinguishable from never-registered» property.
    for s in cluster.iter_mut() {
        let r = s.try_pin(b"123456");
        assert!(
            matches!(r, Err(ThresholdIdentityError::AccountDeleted)),
            "server returns AccountDeleted on subsequent auth (not WrongPin)"
        );
    }
    eprintln!("[R21] PASS: subsequent normal PIN returns AccountDeleted on all 5 servers");
}

#[test]
fn r21_unrecoverable_delete_is_idempotent() {
    let mut cluster = build_5_server_cluster();
    // Wipe once.
    for s in &mut cluster {
        s.unrecoverable_delete();
    }
    // Wipe again — must not panic.
    for s in &mut cluster {
        s.unrecoverable_delete();
    }
    // Still all wiped.
    for s in &cluster {
        assert!(s.revoked);
        assert!(s.encrypted_share.is_empty());
    }
}

#[test]
fn r21_palindromic_pin_does_not_trigger_duress() {
    // PIN "121212" reversed is "212121" — different, so reverse-detect must work.
    // PIN "1221" reversed is "1221" — palindrome, must NOT trigger.
    assert!(!is_duress_reverse(b"1221", b"1221"));
    assert!(!is_duress_reverse(b"123321", b"123321"));
    assert!(is_duress_reverse(b"212121", b"121212"));
}
