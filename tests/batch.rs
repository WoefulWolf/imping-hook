//! Integration tests for batched and unsuspended enabling.

use imping_hook::{Hook, Injection, batch};
use std::hint::black_box;

// Each test hooks its own functions, since all tests share one hook registry.

macro_rules! targets {
    ($($name:ident => $value:expr),* $(,)?) => {
        $(
            #[inline(never)]
            extern "C" fn $name() -> i32 {
                black_box($value)
            }
        )*
    };
}

targets! {
    queued_a => 1,
    queued_b => 2,
    nested_a => 3,
    nested_b => 4,
    moved_a => 5,
    dropped_a => 6,
    last_a => 7,
    unsuspended_a => 8,
    unsuspended_b => 9,
}

extern "C" fn forty_two() -> i32 {
    42
}

/// Installs a hook redirecting `target` to `forty_two`.
fn hook(target: extern "C" fn() -> i32) -> Hook<extern "C" fn() -> i32> {
    // SAFETY: every target here is a real `extern "C" fn() -> i32`, as is the
    // detour.
    unsafe {
        Hook::at(target as *const ())
            .redirect(forty_two as extern "C" fn() -> i32)
            .install()
            .expect("install")
    }
}

/// Installs an injection that runs a `nop` before `target`.
fn injection(target: extern "C" fn() -> i32) -> Injection {
    // SAFETY: the target is a real function whose entry can be relocated, and a
    // `nop` changes nothing it relies on.
    unsafe {
        Injection::at(target as *const ())
            .code(&[0x90])
            .install()
            .expect("install")
    }
}

#[test]
fn changes_in_a_batch_apply_together_when_it_ends() {
    let a = hook(queued_a);
    let b = hook(queued_b);
    let failed = batch(|| {
        a.enable().expect("queued");
        b.enable().expect("queued");
        // Queued, not applied yet.
        assert!(!a.is_enabled());
        assert_eq!(queued_a(), 1);
    });
    assert!(failed.is_empty(), "{failed:?}");
    assert!(a.is_enabled() && b.is_enabled());
    assert_eq!((queued_a(), queued_b()), (42, 42));
}

#[test]
fn a_nested_batch_joins_the_outer_one() {
    let a = hook(nested_a);
    let b = hook(nested_b);
    let failed = batch(|| {
        a.enable().expect("queued");
        let inner = batch(|| b.enable().expect("queued"));
        assert!(inner.is_empty());
        assert!(!b.is_enabled(), "the inner batch does not commit");
    });
    assert!(failed.is_empty(), "{failed:?}");
    assert!(a.is_enabled() && b.is_enabled());
}

#[test]
fn a_queued_patch_can_be_moved_before_the_batch_ends() {
    let mut patches = Vec::new();
    let failed = batch(|| {
        let a = injection(moved_a);
        a.enable().expect("queued");
        // Moving the injection must not invalidate the queued change.
        patches.push(a);
    });
    assert!(failed.is_empty(), "{failed:?}");
    assert!(patches[0].is_enabled());
    assert_eq!(moved_a(), 5);
}

#[test]
fn dropping_a_patch_drops_its_queued_change() {
    let failed = batch(|| {
        let a = hook(dropped_a);
        a.enable().expect("queued");
        drop(a);
    });
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!(dropped_a(), 6, "the dropped hook was never applied");
    // The address is free again.
    drop(hook(dropped_a));
}

#[test]
fn the_last_queued_change_wins() {
    let a = hook(last_a);
    let failed = batch(|| {
        a.enable().expect("queued");
        a.disable().expect("queued");
    });
    assert!(failed.is_empty(), "{failed:?}");
    assert!(!a.is_enabled());
    assert_eq!(last_a(), 7);
}

#[test]
fn unsuspended_changes_apply_at_once_even_in_a_batch() {
    let a = hook(unsuspended_a);
    let b = injection(unsuspended_b);
    // SAFETY: no other thread calls these test-local targets.
    unsafe { a.enable_unsuspended() }.expect("enable");
    assert_eq!(unsuspended_a(), 42);
    let failed = batch(|| {
        b.enable().expect("queued");
        // SAFETY: as above.
        unsafe { b.disable_unsuspended() }.expect("disable");
        assert!(!b.is_enabled());
        // SAFETY: as above.
        unsafe { a.disable_unsuspended() }.expect("disable");
        assert_eq!(unsuspended_a(), 8, "restored at once");
    });
    assert!(failed.is_empty(), "{failed:?}");
    assert!(
        !b.is_enabled(),
        "the unsuspended change replaced the queued one"
    );
}
