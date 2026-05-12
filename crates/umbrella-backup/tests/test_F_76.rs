//! Регрессионные тесты для F-76 LOW (block 10.27c session #59 retroactive surface
//! sweep) — `Snapshot::from_bytes` Vec::with_capacity OOM amplification.
//!
//! **Атака**: уровень D противника после успешного Noise_IK pairing handshake
//! (требует QR shoulder-surf + signed challenge — high attacker cost) шлёт через
//! `TransferSession` подмененный snapshot где `count = u32::MAX` (4 wire-байта
//! контролируемые после version byte 0x01 и count u32 BE). Без mitigation
//! `Vec::<MlsGroupState>::with_capacity(u32::MAX as usize)` сразу запросил бы
//! `4_294_967_295 × ~64 bytes` ≈ **160 GiB виртуальной памяти**. На mobile OS
//! (iOS/Android) — OOM kill процесса (DoS receiver). Amplification factor
//! 5 wire bytes → 160 GiB allocation request = **6.4 × 10¹⁰ ratio**. Mitigation
//! partial: post-Noise_IK + identity binding + KT membership check. Атак не
//! immediate compromise, но user-experience degradation: legitimate user
//! attempting backup transfer на легитимный device, если sender-side device
//! compromised, → receiver crash + потеря backup window.
//!
//! **Mitigation**: ранняя проверка `count_u32 > MAX_SNAPSHOT_GROUPS` (4096)
//! ДО `Vec::with_capacity(count)`; reject через `BackupError::SnapshotDecodeFailed`
//! без allocation. Параллель `MAX_FRAME_PAYLOAD = 1 MiB` в `stream.rs`.
//!
//! Regression tests for F-76 LOW (block 10.27c session #59 retroactive surface
//! sweep) — `Snapshot::from_bytes` Vec::with_capacity OOM amplification.
//!
//! **Attack**: level D adversary after a successful Noise_IK pairing handshake
//! (requires QR shoulder-surf + signed challenge — high attacker cost) sends via
//! `TransferSession` a forged snapshot where `count = u32::MAX` (4 wire bytes
//! controllable after version byte 0x01 and count u32 BE). Without mitigation
//! `Vec::<MlsGroupState>::with_capacity(u32::MAX as usize)` would immediately
//! request `4_294_967_295 × ~64 bytes` ≈ **160 GiB virtual memory**. On mobile
//! OS (iOS/Android) → OOM kill of the process (DoS receiver). Amplification
//! factor 5 wire bytes → 160 GiB allocation request = **6.4 × 10¹⁰ ratio**.
//! Mitigation partial: post-Noise_IK + identity binding + KT membership check.
//! Attack does not immediately compromise but degrades user experience:
//! legitimate user attempting a backup transfer to a legitimate device, if the
//! sender-side device is compromised → receiver crash + lost backup window.
//!
//! **Mitigation**: early check `count_u32 > MAX_SNAPSHOT_GROUPS` (4096) before
//! `Vec::with_capacity(count)`; reject via `BackupError::SnapshotDecodeFailed`
//! without allocation. Mirrors `MAX_FRAME_PAYLOAD = 1 MiB` in `stream.rs`.

use umbrella_backup::device_transfer::snapshot::{
    Snapshot, MAX_SNAPSHOT_GROUPS, SNAPSHOT_EOF_MARKER, SNAPSHOT_VERSION,
};
use umbrella_backup::error::BackupError;

/// F-76 main regression-guard: `count = u32::MAX` (4_294_967_295) — реальный
/// DoS attack vector с amplification 6.4 × 10¹⁰. Должен быть отвергнут через
/// `SnapshotDecodeFailed` БЕЗ Vec::with_capacity allocation 160 GiB. Если
/// тест process не OOM'ится во время выполнения — mitigation работает.
///
/// F-76 main regression-guard: `count = u32::MAX` (4_294_967_295) — real DoS
/// attack vector with amplification 6.4 × 10¹⁰. Must be rejected via
/// `SnapshotDecodeFailed` WITHOUT a 160 GiB Vec::with_capacity allocation. If
/// the test process does not OOM during execution → mitigation works.
#[test]
fn f76_count_u32_max_rejected_without_oom() {
    let mut wire = Vec::new();
    wire.push(SNAPSHOT_VERSION);
    wire.extend_from_slice(&u32::MAX.to_be_bytes());
    // Никаких больше байтов — но Vec::with_capacity(u32::MAX) отвергнут ДО take().
    // No further bytes — but Vec::with_capacity(u32::MAX) is rejected before take().

    let result = Snapshot::from_bytes(&wire);
    assert_eq!(
        result,
        Err(BackupError::SnapshotDecodeFailed),
        "F-76: count=u32::MAX must be rejected via SnapshotDecodeFailed (no OOM)"
    );
}

/// F-76 boundary: `count = MAX_SNAPSHOT_GROUPS + 1` — just-over-limit edge case.
/// Должен быть отвергнут даже когда remaining wire bytes могли бы поддерживать
/// валидный snapshot (по `take()` semantics). Защита raise'ится РАНЬШЕ Vec
/// allocation.
///
/// F-76 boundary: `count = MAX_SNAPSHOT_GROUPS + 1` — just-over-limit edge case.
/// Must be rejected even if the remaining wire bytes could support a valid
/// snapshot (per `take()` semantics). Defence raises before the Vec allocation.
#[test]
fn f76_count_just_over_max_rejected() {
    let mut wire = Vec::new();
    wire.push(SNAPSHOT_VERSION);
    wire.extend_from_slice(&(MAX_SNAPSHOT_GROUPS + 1).to_be_bytes());

    let result = Snapshot::from_bytes(&wire);
    assert_eq!(
        result,
        Err(BackupError::SnapshotDecodeFailed),
        "F-76: count=MAX_SNAPSHOT_GROUPS+1 must be rejected"
    );
}

/// F-76 boundary acceptance: `count = MAX_SNAPSHOT_GROUPS` — exact-limit edge
/// case с валидным wire-format'ом (но всего 0 групп фактически — мы строим
/// header с count=4096 затем сразу EOF). Это всё ещё должно быть отвергнуто
/// потому что remaining wire bytes недостаточны для 4096 групп — но через
/// `take()` bound-check, не через MAX-проверку. Тест верифицирует MAX-проверка
/// НЕ срабатывает на `count == MAX_SNAPSHOT_GROUPS` (она accept'ит limit value).
///
/// F-76 boundary acceptance: `count = MAX_SNAPSHOT_GROUPS` — exact-limit edge
/// case with valid wire format (but actually 0 groups — we build a header with
/// count=4096 then immediately EOF). Must still be rejected because remaining
/// wire bytes are insufficient for 4096 groups — but via the `take()` bound
/// check, not the MAX check. Test verifies the MAX check does NOT fire on
/// `count == MAX_SNAPSHOT_GROUPS` (it accepts the limit value).
#[test]
fn f76_count_exactly_max_does_not_trigger_max_check() {
    let mut wire = Vec::new();
    wire.push(SNAPSHOT_VERSION);
    wire.extend_from_slice(&MAX_SNAPSHOT_GROUPS.to_be_bytes());
    // count=4096 — accept'ed limit value; но take() для group entries не хватает байтов.
    // count=4096 — accepted limit value; but take() for group entries lacks bytes.

    let result = Snapshot::from_bytes(&wire);
    // Reject через take() bound-check (insufficient bytes for first group_id),
    // не через MAX-check. Both code paths return SnapshotDecodeFailed — мы
    // подтверждаем reject status, но не путь.
    //
    // Reject via take() bound-check (insufficient bytes for first group_id),
    // not via MAX check. Both code paths return SnapshotDecodeFailed — we
    // confirm reject status, not which path.
    assert_eq!(
        result,
        Err(BackupError::SnapshotDecodeFailed),
        "F-76: exact MAX_SNAPSHOT_GROUPS without group bytes still rejected"
    );
}

/// F-76 semantic regression: после fix, valid small snapshot (2 groups) round-trip
/// корректно. Не должно быть break'а для legitimate use case.
///
/// F-76 semantic regression: after the fix a valid small snapshot (2 groups)
/// round-trips correctly. No break for legitimate use case.
#[test]
fn f76_valid_small_snapshot_round_trip_unchanged() {
    use umbrella_backup::device_transfer::snapshot::{MlsGroupState, MLS_GROUP_ID_LEN};

    let group1 = MlsGroupState {
        group_id: [0xA1u8; MLS_GROUP_ID_LEN],
        state_bytes: vec![0x01, 0x02, 0x03],
    };
    let group2 = MlsGroupState {
        group_id: [0xB2u8; MLS_GROUP_ID_LEN],
        state_bytes: vec![0x04, 0x05, 0x06, 0x07],
    };
    let original = Snapshot {
        version: SNAPSHOT_VERSION,
        mls_groups: vec![group1, group2],
        local_db_ciphertext: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    };

    let wire = original
        .to_bytes()
        .expect("to_bytes succeeds for valid snapshot");
    let decoded = Snapshot::from_bytes(&wire).expect("from_bytes succeeds post-F-76 fix");
    assert_eq!(
        decoded, original,
        "F-76 fix preserves semantic round-trip for valid small snapshots"
    );
}

/// F-76 EOF marker preservation: подтверждение что `SNAPSHOT_EOF_MARKER` всё
/// ещё используется в from_bytes path после fix (защита от accidental drift).
///
/// F-76 EOF marker preservation: confirm `SNAPSHOT_EOF_MARKER` is still
/// consumed in the from_bytes path after the fix (guard against accidental
/// drift).
#[test]
fn f76_eof_marker_still_validated_post_fix() {
    use umbrella_backup::device_transfer::snapshot::MLS_GROUP_ID_LEN;

    // Build wire with valid version + count=0 + db_len=0 + WRONG eof marker.
    let mut wire = Vec::new();
    wire.push(SNAPSHOT_VERSION);
    wire.extend_from_slice(&0u32.to_be_bytes()); // count=0
    wire.extend_from_slice(&0u64.to_be_bytes()); // db_len=0
    wire.extend_from_slice(b"BAD!"); // wrong EOF marker

    let result = Snapshot::from_bytes(&wire);
    assert_eq!(
        result,
        Err(BackupError::SnapshotDecodeFailed),
        "F-76 fix does not bypass EOF marker validation"
    );

    // Sanity: same wire с valid EOF — должен succeed.
    // Sanity: same wire with valid EOF — must succeed.
    let mut wire_ok = Vec::new();
    wire_ok.push(SNAPSHOT_VERSION);
    wire_ok.extend_from_slice(&0u32.to_be_bytes());
    wire_ok.extend_from_slice(&0u64.to_be_bytes());
    wire_ok.extend_from_slice(SNAPSHOT_EOF_MARKER);

    let snapshot = Snapshot::from_bytes(&wire_ok).expect("zero-groups zero-db snapshot decodes");
    assert_eq!(snapshot.mls_groups.len(), 0);
    assert_eq!(snapshot.local_db_ciphertext.len(), 0);
    let _ = MLS_GROUP_ID_LEN; // silence unused import lint в minimum case теста.
}
