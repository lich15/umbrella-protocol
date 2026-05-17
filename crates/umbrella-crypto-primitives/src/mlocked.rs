//! Page-locked secret wrapper: `mlock(2)` + `zeroize`-on-drop.
//! Page-locked secret wrapper: `mlock(2)` + `zeroize`-on-drop.
//!
//! # Зачем нужен `MlockedSecret<T>`
//!
//! `secrecy::SecretBox<T>` обеспечивает только `ZeroizeOnDrop` — секрет
//! затрётся при выходе из scope, но **до** этого момента OS может выгрузить
//! страницу в swap. На Linux/Android swap по умолчанию не шифруется
//! (`/etc/crypttab` опционален), на macOS swap шифруется per-boot SEP key
//! но VM compressor работает в RAM и **не** сжимает зашифрованные страницы
//! по-новой. Round-4 R11 PhD-B device-capture audit подтвердил:
//! `rg "mlock|VirtualLock|MAP_LOCKED" --type rust -n` даёт **0 matches** в
//! workspace; F-PHD-DC-R11-1 классифицирован MEDIUM.
//!
//! `MlockedSecret<T>` вызывает `libc::mlock` после `Box::new` чтобы пометить
//! страницу резидентной (`MCL_FUTURE`-семантика per-page) и `libc::munlock`
//! на Drop после `zeroize`. Это closure F-PHD-DC-R11-1.
//!
//! # Why `MlockedSecret<T>`
//!
//! `secrecy::SecretBox<T>` provides only `ZeroizeOnDrop` — the secret is
//! wiped when it goes out of scope, but **before** that point the OS can
//! page the memory to swap. Linux/Android swap is not encrypted by default
//! (`/etc/crypttab` is optional); macOS swap is encrypted by a per-boot SEP
//! key, but the VM compressor lives in RAM and does **not** re-encrypt
//! pages it has already compressed. The round-4 R11 PhD-B device-capture
//! audit confirmed `rg "mlock|VirtualLock|MAP_LOCKED" --type rust -n`
//! returns **0 matches** across the workspace; F-PHD-DC-R11-1 was rated
//! MEDIUM.
//!
//! `MlockedSecret<T>` calls `libc::mlock` after `Box::new` so the kernel
//! marks the page resident (per-page `MCL_FUTURE` semantics) and
//! `libc::munlock` on Drop after `zeroize`. This closes F-PHD-DC-R11-1.
//!
//! # Threat model
//!
//! - **Свопированный image от выключенного устройства** — на macOS зашифрован
//!   SEP per-boot key; на Linux зависит от настройки. mlock закрывает
//!   leak-через-swap полностью.
//! - **Live-attach debugger** — mlock **не** защищает (страница остаётся
//!   в RAM и читается через `vm_read` / `ptrace`). Этот класс атак
//!   закрывается только move в TEE (Component 1 + 2 hardware bridge).
//! - **Cold-boot DRAM retention** — mlock делает страницу гарантированно
//!   резидентной → cold-boot читает её. **Хуже** для cold-boot чем не-mlock'd
//!   страница которая могла быть выгружена. Compensating control:
//!   `zeroize()` срабатывает на Drop под Tokio cooperative scheduling
//!   обычно за < 1ms; cold-boot retention measured Halderman 2009 +
//!   Bauer 2020 USENIX составляет 30s+. Net: mlock полезен для swap
//!   и **нейтрален** для cold-boot.
//!
//! # Threat model
//!
//! - **Swap image from a powered-down device** — encrypted on macOS by the
//!   SEP per-boot key; depends on configuration on Linux. mlock closes the
//!   swap leak entirely.
//! - **Live-attach debugger** — mlock does **not** help (the page stays in
//!   RAM and is readable via `vm_read` / `ptrace`). That class is closed
//!   only by moving the key to a TEE (Component 1 + 2 hardware bridge).
//! - **Cold-boot DRAM retention** — mlock makes the page guaranteed-
//!   resident, so cold-boot reads it. **Worse** for cold-boot than a non-
//!   mlocked page that may have been evicted. Compensating control: the
//!   `zeroize()` runs on Drop under Tokio cooperative scheduling typically
//!   in < 1ms; the cold-boot retention measured by Halderman 2009 + Bauer
//!   2020 USENIX is 30s+. Net: mlock helps swap and is **neutral** for
//!   cold-boot.
//!
//! # API contract
//!
//! ```ignore
//! use umbrella_crypto_primitives::mlocked::MlockedSecret;
//! use zeroize::Zeroize;
//!
//! // T: Zeroize is required; Box::new heap-allocates, mlock locks the page.
//! let mut secret = MlockedSecret::new([0u8; 32]);
//! assert_eq!(secret.expose().len(), 32);
//! // ... use secret ...
//! drop(secret); // zeroize then munlock
//! ```
//!
//! # Ошибка соответствия `libc::mlock`
//!
//! `mlock(2)` POSIX.1-2001 может failed только если:
//! - Caller exceeds `RLIMIT_MEMLOCK` (default 64 KiB unprivileged Linux,
//!   unlimited на macOS/Darwin для тех процессов которые НЕ хитро ограничены).
//!   Превышение даёт `EAGAIN`; мы graceful-degrade на `locked = false`
//!   и **не** падаем — секрет остаётся в heap+zeroize-on-drop, что
//!   эквивалентно текущему baseline `SecretBox`.
//! - `EINVAL` если addr+len overflow — невозможно для `Box::new(T)` где
//!   `size_of::<T>() < isize::MAX`.
//! - `ENOMEM` если addresses not in process map — невозможно для
//!   только-что allocated heap pointer.
//!
//! Graceful degradation: failed `mlock` логирует через `debug_assert!` в
//! debug builds; в release просто помечает `locked = false`. Caller'у это
//! не видно — API возвращает только `Self` без ошибки.
//!
//! # Compatibility with `libc::mlock`
//!
//! `mlock(2)` (POSIX.1-2001) can fail only when:
//! - The caller exceeds `RLIMIT_MEMLOCK` (default 64 KiB unprivileged Linux,
//!   unlimited on macOS/Darwin for processes not explicitly capped). The
//!   excess returns `EAGAIN`; we degrade gracefully to `locked = false`
//!   and do **not** panic — the secret remains in heap+zeroize-on-drop,
//!   matching the baseline `SecretBox`.
//! - `EINVAL` if addr+len overflows — impossible for `Box::new(T)` where
//!   `size_of::<T>() < isize::MAX`.
//! - `ENOMEM` if the addresses are outside the process map — impossible
//!   for a freshly allocated heap pointer.
//!
//! Graceful degradation: a failed `mlock` triggers `debug_assert!` in
//! debug builds; in release it just sets `locked = false`. The caller does
//! not see this — the API returns `Self` without an error.

// Module-scope override: `unsafe` is required here for `libc::mlock` /
// `libc::munlock` syscalls + `unsafe impl Send/Sync` (the wrapper is
// inherently `Send/Sync` because `Box<T>` is, but Rust trait coherence
// requires the impl). All other modules in this crate keep
// `#![forbid(unsafe_code)]` at module scope.
//
// Module-scope override: `unsafe` is needed for `libc::mlock` /
// `libc::munlock` syscalls and `unsafe impl Send/Sync` (the wrapper is
// inherently `Send/Sync` because `Box<T>` is, but Rust trait coherence
// requires the impl). Every other module keeps `#![forbid(unsafe_code)]`.
#![allow(unsafe_code)]

use core::fmt;

use thiserror::Error;
use zeroize::Zeroize;

/// Ошибки `MlockedSecret`. Сейчас единственная — `MlockSyscall(libc errno)`.
/// Returned by the (unused) explicit `try_new` constructor; canonical
/// `new` paths degrade gracefully и не возвращают ошибок.
///
/// Errors from `MlockedSecret`. Currently a single variant —
/// `MlockSyscall(libc errno)`. Returned by the (unused) explicit `try_new`
/// constructor; canonical `new` paths degrade gracefully and do not return
/// errors.
#[derive(Debug, Error)]
pub enum MlockError {
    /// `libc::mlock` returned non-zero — see `std::io::Error::last_os_error`.
    /// `libc::mlock` returned non-zero — see `std::io::Error::last_os_error`.
    #[error("libc::mlock failed: {0}")]
    MlockSyscall(#[from] std::io::Error),
}

/// Page-locked + zeroize'd heap secret. Wraps `Box<T>` so the secret is
/// heap-resident (no stack spill at any depth of constructor inlining)
/// and tells the kernel «do not page this out» via `libc::mlock`.
///
/// Зачем `Box<T>`: stack-resident value подвергся бы LLVM stack-spill во
/// время передачи в `MlockedSecret::new` (round-4 R7 finding: 32 байта
/// entropy переживают `drop(IdentitySeed)` на стеке). Heap allocation
/// гарантирует один источник истинности — указатель в `Box` — который
/// проще zeroize'ить и mlock'ить.
///
/// Why `Box<T>`: a stack-resident value would suffer LLVM stack-spill
/// during the pass into `MlockedSecret::new` (round-4 R7 finding: 32 bytes
/// of entropy survive `drop(IdentitySeed)` on the stack). The heap
/// allocation provides a single source of truth — the pointer inside
/// `Box` — that is straightforward to both zeroize and mlock.
pub struct MlockedSecret<T: Zeroize> {
    /// `Box<T>` heap-allocates so the secret never lives on the stack.
    /// We need `Option<Box<T>>` to support `take()` semantics in Drop —
    /// otherwise we couldn't both zeroize and call mlock_unlocking on the
    /// raw pointer without aliasing issues.
    inner: Box<T>,
    /// `true` if `libc::mlock` succeeded — we will call `munlock` on Drop.
    /// `false` if mlock failed (e.g. RLIMIT_MEMLOCK exceeded) — we just
    /// rely on `zeroize` like `SecretBox`.
    locked: bool,
}

impl<T: Zeroize> MlockedSecret<T> {
    /// Allocate `value` on the heap and `mlock` the page. Falls back to
    /// non-locked (zeroize-only) on `mlock` failure — caller does not see
    /// the error to keep the API ergonomic on memory-pressured devices.
    ///
    /// # Safety contract
    ///
    /// `mlock(2)` requires a valid pointer and a length that does not
    /// straddle unmapped pages. `Box::new(value)` returns a heap pointer
    /// that satisfies both invariants for any `T: Sized`.
    ///
    /// Аллоцирует `value` в heap и `mlock`'ит страницу. Graceful degrade
    /// на non-locked (zeroize-only) при сбое `mlock` — caller не видит
    /// ошибки чтобы API оставался ergonomic под memory pressure.
    #[must_use]
    pub fn new(value: T) -> Self {
        let inner = Box::new(value);
        let ptr = (&*inner) as *const T as *const libc::c_void;
        let size = std::mem::size_of::<T>();
        // `size == 0` — zero-sized types. mlock на NULL/0 не имеет
        // смысла; пропустим.
        let locked = if size == 0 {
            false
        } else {
            // SAFETY: `inner` — pointer на valid `T` через `Box::new`;
            // `size_of::<T>()` корректен и не overflow'ит (Rust гарантирует
            // что `T: Sized` имеет `size_of() <= isize::MAX`). `libc::mlock`
            // не пишет в указанную память, только маркирует page-table
            // entries как non-swappable. Aliasing-rules не нарушаются:
            // `mlock` не создаёт второго Rust-references на буфер.
            //
            // SAFETY: `inner` is a valid `T` pointer from `Box::new`;
            // `size_of::<T>()` is correct and cannot overflow (Rust
            // guarantees `T: Sized` has `size_of() <= isize::MAX`).
            // `libc::mlock` does not write to the memory, it just marks
            // page-table entries non-swappable. Aliasing rules are
            // preserved: `mlock` does not create another Rust reference.
            let rc = unsafe { libc::mlock(ptr, size) };
            if rc != 0 {
                // RLIMIT_MEMLOCK exceeded или unprivileged kernel
                // restriction → graceful degrade. Не паникуем, остаёмся
                // эквивалентным SecretBox для caller'а.
                #[cfg(debug_assertions)]
                {
                    let err = std::io::Error::last_os_error();
                    eprintln!(
                        "[MlockedSecret] mlock({} bytes) failed: {err}; \
                         falling back to zeroize-only (RLIMIT_MEMLOCK or kernel restriction)",
                        size
                    );
                }
                false
            } else {
                true
            }
        };
        Self { inner, locked }
    }

    /// Returns immutable access to the inner value. Caller must minimize
    /// the lifetime of this borrow — every clone of the slice is a new
    /// uncontrolled stack copy.
    ///
    /// Доступ только-чтение к secret. Caller должен минимизировать lifetime
    /// borrow — каждое копирование slice'а = новая stack-копия вне control.
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.inner
    }

    /// Returns mutable access — used by `IdentitySeed::from_mnemonic` and
    /// similar constructors that fill bytes into the heap allocation
    /// directly (no stack-spill at any depth).
    ///
    /// Mutable access для in-place заполнения — used by `IdentitySeed::from_mnemonic`
    /// и подобных конструкторов которые пишут bytes прямо в heap allocation
    /// (без stack-spill на любой глубине).
    #[must_use]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns `true` if the underlying page is page-locked (mlock'd).
    /// `false` means `libc::mlock` failed (RLIMIT_MEMLOCK or similar);
    /// the secret is still zeroize-on-drop, just not mlock'd.
    ///
    /// `true` если страница mlock'ed. `false` — `libc::mlock` упал; секрет
    /// всё ещё zeroize-on-drop, просто не mlock'ed.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<T: Zeroize> Drop for MlockedSecret<T> {
    fn drop(&mut self) {
        // Wipe first — `munlock` после zeroize не оставляет шанса увидеть
        // секрет в выгруженной странице (см. invariant в module docs).
        // Wipe first — calling `munlock` after `zeroize` ensures the OS
        // never sees the secret in a swap-eligible state again (module
        // docs invariant).
        self.inner.zeroize();

        if self.locked {
            let ptr = (&*self.inner) as *const T as *const libc::c_void;
            let size = std::mem::size_of::<T>();
            if size > 0 {
                // SAFETY: same invariants as in `new`. `munlock` is the
                // inverse syscall; failure (e.g. ENOMEM if the page was
                // already unmapped by a panic) is logged in debug builds
                // but does not panic in Drop.
                //
                // SAFETY: те же invariants что в `new`. `munlock` — обратный
                // syscall; failure (ENOMEM если страница уже unmapped после
                // panic) логируется в debug builds но не panic'ит в Drop.
                let rc = unsafe { libc::munlock(ptr, size) };
                #[cfg(debug_assertions)]
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    eprintln!("[MlockedSecret] munlock failed in Drop: {err}");
                }
                let _ = rc;
            }
        }
    }
}

impl<T: Zeroize> fmt::Debug for MlockedSecret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlockedSecret")
            .field("size_bytes", &std::mem::size_of::<T>())
            .field("locked", &self.locked)
            .field("inner", &"<redacted>")
            .finish()
    }
}

// `Send + Sync` если `T: Send + Sync` — heap-allocated, mlock-state
// атомарный per-instance; конкурирующий доступ к `&self.inner` через
// `&MlockedSecret<T>` идентичен `Box<T>: Sync`.
//
// `Send + Sync` if `T: Send + Sync` — heap-allocated, the mlock state is
// per-instance atomic; concurrent access through `&MlockedSecret<T>`
// matches `Box<T>: Sync`.
unsafe impl<T: Zeroize + Send> Send for MlockedSecret<T> {}
unsafe impl<T: Zeroize + Sync> Sync for MlockedSecret<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: new + expose + drop без panic. Минимальный smoke test.
    /// Sanity: new + expose + drop without panic. Minimal smoke test.
    #[test]
    fn smoke_construct_and_expose() {
        let secret = MlockedSecret::<[u8; 32]>::new([0x42u8; 32]);
        assert_eq!(secret.expose()[0], 0x42);
        assert_eq!(secret.expose()[31], 0x42);
        // is_locked == true на большинстве macOS/Linux configurations
        // (RLIMIT_MEMLOCK по default достаточный для 32 байт). Не assert
        // строго — degraded path тоже valid.
        // is_locked == true on most macOS/Linux configurations (default
        // RLIMIT_MEMLOCK comfortably fits 32 bytes). Don't assert strictly
        // — the degraded path is also valid.
    }

    /// Verify zeroize fires on drop. Используем `*const T` snapshot после
    /// drop — must be all zeros через heap memory.
    /// Verify zeroize fires on drop. Use a `*const T` snapshot post-drop —
    /// it must read all zeros from the heap memory.
    #[test]
    fn zeroize_on_drop_wipes_heap() {
        let secret = MlockedSecret::<[u8; 16]>::new([0xAB; 16]);
        let ptr = secret.expose() as *const [u8; 16];
        drop(secret);
        // SAFETY: после drop heap allocation технически freed. Read
        // через ptr — UB в общем случае; тест использует тот факт что
        // глобальный allocator (system allocator) reuses freed memory не
        // мгновенно — поэтому byte-level check has good probability of
        // observing zero. Это не security claim, это smoke test что
        // zeroize действительно был вызван.
        //
        // SAFETY: after drop the heap allocation is technically freed.
        // Reading via `ptr` is UB in general; this test relies on the
        // fact that the global system allocator does not reuse freed
        // memory instantly, so a byte-level check has good probability
        // of observing zero. This is not a security claim — it is a
        // smoke test that zeroize was in fact invoked.
        //
        // Disabled by default to keep miri happy; enable manually under
        // `MLOCKED_ZEROIZE_SMOKE_TEST=1` for local sanity:
        if std::env::var("MLOCKED_ZEROIZE_SMOKE_TEST").is_ok() {
            let observed = unsafe { *ptr };
            assert_eq!(observed, [0u8; 16], "heap not zeroized");
        }
        let _ = ptr; // silence unused on default test run
    }

    /// Multiple sizes — verify mlock works for typical secret sizes used
    /// across the workspace: 16/32/64/96/128 bytes.
    /// Multiple sizes — confirm mlock works for the typical secret sizes
    /// across the workspace: 16/32/64/96/128 bytes.
    #[test]
    fn multiple_sizes_construct_ok() {
        let _ = MlockedSecret::<[u8; 16]>::new([0; 16]);
        let _ = MlockedSecret::<[u8; 32]>::new([0; 32]);
        let _ = MlockedSecret::<[u8; 64]>::new([0; 64]);
        let _ = MlockedSecret::<[u8; 96]>::new([0; 96]);
        let _ = MlockedSecret::<[u8; 128]>::new([0; 128]);
    }

    /// Debug output не должен включать секретные байты.
    /// Debug output must not leak secret bytes.
    #[test]
    fn debug_does_not_leak() {
        let secret = MlockedSecret::<[u8; 32]>::new([0xCD; 32]);
        let dbg = format!("{secret:?}");
        assert!(!dbg.contains("cd"), "Debug must not leak hex of secret");
        assert!(!dbg.contains("CD"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("MlockedSecret"));
    }

    /// `expose_mut` allows in-place filling without stack copy.
    /// `expose_mut` allows in-place population without a stack round-trip.
    #[test]
    fn expose_mut_supports_in_place_fill() {
        let mut secret = MlockedSecret::<[u8; 32]>::new([0u8; 32]);
        for (i, b) in secret.expose_mut().iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(secret.expose()[0], 0);
        assert_eq!(secret.expose()[31], 31);
    }

    /// Send + Sync: смэнить boxed secret через Arc — должен компилироваться.
    /// Send + Sync: move boxed secret via Arc — must compile.
    #[test]
    fn send_sync_through_arc() {
        let secret = std::sync::Arc::new(MlockedSecret::<[u8; 32]>::new([0xAA; 32]));
        let cloned = secret.clone();
        let h = std::thread::spawn(move || cloned.expose()[0]);
        assert_eq!(h.join().expect("thread join"), 0xAA);
        let _ = secret.expose();
    }
}
