//! Регрессионные тесты для F-77 LOW (block 10.27d session #59 follow-up
//! к block 10.27c retroactive surface sweep) — `FixedWindow.allow()`
//! unbounded sender_id HashMap growth в default in-memory implementation.
//!
//! **Атака**: уровень D противника (state-level) создаёт миллионы
//! уникальных `sender_id` значений в секунду через подделанные
//! отправители; `self.buckets.entry(sender_id.to_vec()).or_insert(...)`
//! аллоцирует `Vec<u8>` per unique sender; до этого fix не было
//! `max_senders` cap либо TTL-based eviction. С `sender_id` обычно
//! 32-byte Ed25519-pubkey-производным → ~32 bytes per entry × 10M
//! unique = **~320 МБ/сек прироста памяти на сервере**, OOM-driven
//! crash. Threat row: out-of-table «server availability / DoS protection»
//! (analog F-55 closure block 10.14).
//!
//! **Severity LOW**: docstring lib.rs:7-8 + ratelimit.rs:6-7 documents
//! «production backend в `Umbrella server implementation` использует Valkey/DragonflyDB через
//! FFI» — default in-memory `FixedWindow` только для tests/dev/local;
//! production path имеет Valkey-backed sliding-window с capacity controls.
//! F-77 это adjacent unbounded-growth gap defence-in-depth.
//!
//! **Mitigation**: жёсткий потолок `MAX_TRACKED_SENDERS = 100_000`. При
//! достижении лимита `allow()` сначала чистит просроченные окна
//! (retain bucket'ов с актуальным `window_start`), потом если table
//! всё ещё full — отвергает новых отправителей (fail-closed). Существующие
//! отправители продолжают работать без изменений.
//!
//! Regression tests for F-77 LOW (block 10.27d session #59 follow-up to
//! block 10.27c retroactive surface sweep) — `FixedWindow.allow()`
//! unbounded sender_id HashMap growth in the default in-memory
//! implementation.
//!
//! **Attack**: level D adversary (state-level) creates millions of unique
//! `sender_id` values per second via forged senders; before this fix
//! there was no `max_senders` cap or TTL-based eviction. With ~32-byte
//! Ed25519-pubkey-derived sender_id → ~32 bytes per entry × 10M unique
//! = **~320 MB/sec memory growth on the server**, OOM-driven crash.
//!
//! **Severity LOW**: docstring documents production uses Valkey/DragonflyDB;
//! default in-memory `FixedWindow` is for tests/dev/local. F-77 is an
//! adjacent defence-in-depth unbounded-growth gap.
//!
//! **Mitigation**: hard cap `MAX_TRACKED_SENDERS = 100_000`. On reaching
//! the limit `allow()` first cleans expired windows (retaining only
//! buckets with the current `window_start`), then if the table is still
//! full — rejects new senders (fail-closed). Existing senders keep
//! working without change.

use umbrella_server_blind_postman::ratelimit::{FixedWindow, RateLimiter, MAX_TRACKED_SENDERS};

/// F-77 sanity: behaviour под cap идентично pre-fix. Existing test suite
/// `fixed_window_allows_up_to_limit` etc. covers нормальный flow; этот
/// тест дополнительно подтверждает что добавленная capacity-проверка не
/// влияет на стандартный путь.
///
/// F-77 sanity: behaviour under cap is identical to pre-fix. The existing
/// `fixed_window_allows_up_to_limit` etc. cover the normal flow; this test
/// additionally confirms that the added capacity check does not affect
/// the standard path.
#[test]
fn f77_under_capacity_unchanged_behaviour() {
    let mut rl = FixedWindow::new(60, 5);
    // 3 senders × 5 сообщений = 15 calls; far below MAX_TRACKED_SENDERS.
    // 3 senders × 5 messages = 15 calls; far below MAX_TRACKED_SENDERS.
    for sender in [b"alice".as_slice(), b"bob".as_slice(), b"carol".as_slice()] {
        for _ in 0..5 {
            assert!(rl.allow(sender, 100), "allow under capacity must succeed");
        }
        assert!(
            !rl.allow(sender, 100),
            "6th message in window must be blocked (per_window=5)"
        );
    }
    assert_eq!(
        rl.active_senders(),
        3,
        "3 unique senders tracked under capacity"
    );
}

/// F-77 main regression-guard: при `MAX_TRACKED_SENDERS` уникальных
/// отправителей в одном окне новый отправитель отвергается (fail-closed)
/// после неудачной попытки очистки просроченных окон. Существующий
/// отправитель в этом наборе продолжает работать.
///
/// F-77 main regression-guard: at `MAX_TRACKED_SENDERS` unique senders in
/// a single window, a new sender is rejected (fail-closed) after a failed
/// expired-window cleanup attempt. An existing sender in the set keeps
/// working.
#[test]
fn f77_at_capacity_in_same_window_rejects_new_senders() {
    let mut rl = FixedWindow::new(60, 100);
    // Заполняем table до лимита уникальными sender_id в одном окне (now_unix=100).
    // Fill the table to cap with unique sender_id values in one window (now_unix=100).
    for i in 0..MAX_TRACKED_SENDERS {
        let sender = (i as u64).to_le_bytes();
        assert!(
            rl.allow(&sender, 100),
            "sender {i} must be admitted under capacity"
        );
    }
    assert_eq!(
        rl.active_senders(),
        MAX_TRACKED_SENDERS,
        "table filled to cap"
    );

    // Новый отправитель в том же окне — все существующие entries имеют
    // window_start=60 (`(100 / 60) * 60 = 60`); cleanup retain'ит все,
    // table остаётся full → reject.
    //
    // New sender in the same window — all existing entries have
    // window_start=60 (`(100 / 60) * 60 = 60`); cleanup retains all,
    // the table stays full → reject.
    let newbie = b"newbie_attacker";
    assert!(
        !rl.allow(newbie, 100),
        "F-77: new sender at capacity in same window must be rejected (fail-closed)"
    );

    // Существующий отправитель продолжает работать (не triggers cleanup).
    // Existing sender keeps working (does not trigger cleanup).
    let existing = (0u64).to_le_bytes();
    assert!(
        rl.allow(&existing, 100),
        "F-77: existing sender at capacity must keep working"
    );
}

/// F-77 cleanup admits new senders after window advance: при заполнении
/// table в старом окне и продвижении времени к новому окну, cleanup
/// удаляет все просроченные buckets и admits нового отправителя.
///
/// F-77 cleanup admits new senders after window advance: when the table is
/// filled in an old window and time advances to a new window, cleanup
/// removes all expired buckets and admits the new sender.
#[test]
fn f77_cleanup_admits_new_senders_after_window_advance() {
    let mut rl = FixedWindow::new(60, 100);
    // Заполняем table в окне [60, 120).
    // Fill the table in window [60, 120).
    for i in 0..MAX_TRACKED_SENDERS {
        let sender = (i as u64).to_le_bytes();
        assert!(rl.allow(&sender, 100), "sender {i} admitted");
    }
    assert_eq!(rl.active_senders(), MAX_TRACKED_SENDERS);

    // Время продвигается к новому окну [180, 240). Все existing buckets
    // имеют window_start=60, новый window_start=180. Новый отправитель
    // triggers cleanup (which evicts all old-window entries), затем
    // admits как первая запись в новом окне.
    //
    // Time advances to new window [180, 240). All existing buckets have
    // window_start=60, the new window_start=180. New sender triggers
    // cleanup (evicting all old-window entries), then is admitted as the
    // first entry in the new window.
    let newbie = b"newbie_legitimate";
    assert!(
        rl.allow(newbie, 200),
        "F-77: new sender after window advance admitted via cleanup"
    );
    // После cleanup table содержит только newbie (все старые удалены).
    // After cleanup the table contains only newbie (all old entries gone).
    assert_eq!(
        rl.active_senders(),
        1,
        "F-77: cleanup evicted all expired-window buckets"
    );
}

/// F-77 cleanup partially preserves senders that crossed window boundary:
/// если часть существующих senders уже сделали запрос в новом окне (их
/// bucket был обновлён), cleanup сохраняет их и evict'ит non-crossed
/// (просроченных) senders, освобождая место для нового. Сценарий:
/// 50 senders crossed → 50 expired → cleanup keeps 50 active → admits new.
///
/// F-77 cleanup partially preserves senders that crossed the window
/// boundary: if some existing senders have already made a request in the
/// new window (their bucket was updated), cleanup retains them and evicts
/// non-crossed (expired) senders, freeing room for a new one. Scenario:
/// 50 senders crossed → 50 expired → cleanup keeps 50 active → admits new.
#[test]
fn f77_cleanup_preserves_senders_active_in_current_window() {
    let mut rl = FixedWindow::new(60, 100);
    // Заполняем table до cap уникальными senders в старом окне (window=60).
    // Fill the table to cap with unique senders in the old window (window=60).
    for i in 0..MAX_TRACKED_SENDERS {
        let sender = (i as u64).to_le_bytes();
        assert!(rl.allow(&sender, 100));
    }
    assert_eq!(rl.active_senders(), MAX_TRACKED_SENDERS);

    // 50 существующих senders переходят в новое окно (их bucket window_start
    // обновляется с 60 на 180). Эти crossings не triggers cleanup (existing
    // entries — `contains_key` returns true → skip cleanup branch).
    //
    // 50 existing senders cross into the new window (their bucket
    // window_start updates from 60 to 180). These crossings do not trigger
    // cleanup (existing entries — `contains_key` returns true → skip
    // cleanup branch).
    const CROSSED: usize = 50;
    for i in 0..CROSSED {
        let sender = (i as u64).to_le_bytes();
        assert!(rl.allow(&sender, 200));
    }
    assert_eq!(
        rl.active_senders(),
        MAX_TRACKED_SENDERS,
        "crossings preserve count (existing entries не deleted)"
    );

    // Новый sender в новом окне triggers cleanup: retain window=180 →
    // оставляет 50 crossed entries, evicts оставшиеся (MAX-50) с window=60.
    // После cleanup len = 50 < MAX → admit нового sender → len = 51.
    //
    // New sender in the new window triggers cleanup: retain window=180 →
    // keeps 50 crossed entries, evicts the remaining (MAX-50) with
    // window=60. After cleanup len = 50 < MAX → admit new sender →
    // len = 51.
    let newbie = b"newbie_after_partial_cleanup";
    assert!(
        rl.allow(newbie, 200),
        "F-77: cleanup of expired entries admits new sender (crossed senders preserved)"
    );

    let final_count = rl.active_senders();
    let expected = CROSSED + 1;
    assert_eq!(
        final_count, expected,
        "F-77: post-cleanup table contains {CROSSED} crossed + 1 new = {expected}"
    );

    // Sanity: один из crossed senders продолжает работать (его bucket
    // preserved через cleanup).
    //
    // Sanity: one of the crossed senders keeps working (its bucket survived
    // cleanup).
    let crossed_sender = (10u64).to_le_bytes();
    assert!(
        rl.allow(&crossed_sender, 200),
        "F-77: crossed sender preserved by cleanup must still work"
    );
}

/// F-77 fail-closed semantics: при заполнении table в актуальном окне
/// (cleanup не помогает потому что все buckets активны), новые
/// отправители systematically отвергаются. Это design choice fail-closed
/// (а не fail-open) — лучше отказать legitimate user-у на overloaded
/// сервере чем дать атакующему OOM-кill процесс.
///
/// F-77 fail-closed semantics: when the table fills up in the current
/// window (cleanup does not help because all buckets are active), new
/// senders are systematically rejected. This is a fail-closed design
/// choice (not fail-open) — better to reject a legitimate user on an
/// overloaded server than to let an attacker OOM-kill the process.
#[test]
fn f77_fail_closed_under_sustained_attack_within_window() {
    let mut rl = FixedWindow::new(60, 100);
    // Симулируем атаку: заполнение table уникальными sender_id'ами.
    // Simulate attack: filling the table with unique sender_ids.
    for i in 0..MAX_TRACKED_SENDERS {
        let sender = (i as u64).to_le_bytes();
        assert!(rl.allow(&sender, 100));
    }

    // Сохраняющиеся попытки атакующего добавить новых senders все
    // отвергаются (fail-closed) поскольку cleanup не освобождает место в
    // том же окне.
    //
    // Sustained attacker attempts to add new senders are all rejected
    // (fail-closed) because cleanup does not free room in the same window.
    for i in MAX_TRACKED_SENDERS..(MAX_TRACKED_SENDERS + 100) {
        let sender = (i as u64).to_le_bytes();
        assert!(
            !rl.allow(&sender, 100),
            "F-77: sustained attack at capacity must be rejected (fail-closed)"
        );
    }

    // Table size остаётся ровно MAX_TRACKED_SENDERS — атакующий не может
    // grow её дальше.
    //
    // The table size stays exactly MAX_TRACKED_SENDERS — the attacker
    // cannot grow it further.
    assert_eq!(
        rl.active_senders(),
        MAX_TRACKED_SENDERS,
        "F-77: table size bounded by MAX_TRACKED_SENDERS under sustained attack"
    );
}
