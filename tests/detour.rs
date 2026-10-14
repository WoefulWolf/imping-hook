//! Integration tests for typed detours.

use imping_hook::{Error, Hook};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

// Each test uses its own target function so that tests, which share the
// process-wide hook registry, never contend for the same address.

#[inline(never)]
extern "C" fn basic_value() -> i32 {
    black_box(1)
}

extern "C" fn basic_detour() -> i32 {
    2
}

#[test]
fn enable_disable_and_original() {
    // SAFETY: `basic_value` is a real function with this signature, and
    // `basic_detour` shares it.
    let hook = unsafe {
        Hook::at(basic_value as *const ())
            .redirect(basic_detour as extern "C" fn() -> i32)
            .install()
            .expect("install")
    };

    assert!(!hook.is_enabled());
    assert_eq!(basic_value(), 1);

    hook.enable().expect("enable");
    assert!(hook.is_enabled());
    assert_eq!(basic_value(), 2);
    // The original is still reachable through the hook.
    assert_eq!(hook.original().call(), 1);

    hook.disable().expect("disable");
    assert!(!hook.is_enabled());
    assert_eq!(basic_value(), 1);
}

#[inline(never)]
extern "C" fn double_hook_value() -> i32 {
    black_box(10)
}

extern "C" fn double_hook_detour() -> i32 {
    20
}

#[test]
fn second_hook_on_same_address_is_refused() {
    // SAFETY: real function, shared signature.
    let first = unsafe {
        Hook::at(double_hook_value as *const ())
            .redirect(double_hook_detour as extern "C" fn() -> i32)
            .install()
            .expect("first install")
    };

    // SAFETY: real function, shared signature.
    let second = unsafe {
        Hook::at(double_hook_value as *const ())
            .redirect(double_hook_detour as extern "C" fn() -> i32)
            .install()
    };
    assert!(matches!(second, Err(Error::AlreadyHooked { .. })));

    // Dropping the first frees the address, so it can be hooked again.
    drop(first);
    // SAFETY: real function, shared signature.
    let third = unsafe {
        Hook::at(double_hook_value as *const ())
            .redirect(double_hook_detour as extern "C" fn() -> i32)
            .install()
    };
    assert!(third.is_ok());
}

#[inline(never)]
extern "C" fn drop_value() -> i32 {
    black_box(100)
}

extern "C" fn drop_detour() -> i32 {
    200
}

#[test]
fn drop_unhooks() {
    {
        // SAFETY: real function, shared signature.
        let hook = unsafe {
            Hook::at(drop_value as *const ())
                .redirect(drop_detour as extern "C" fn() -> i32)
                .install()
                .expect("install")
        };
        hook.enable().expect("enable");
        assert_eq!(drop_value(), 200);
    }
    // After the guard is dropped the original behaviour is restored.
    assert_eq!(drop_value(), 100);
}

#[inline(never)]
extern "C" fn leak_value() -> i32 {
    black_box(7)
}

extern "C" fn leak_detour() -> i32 {
    8
}

#[test]
fn leak_keeps_hook_and_returns_original() {
    // SAFETY: real function, shared signature.
    let hook = unsafe {
        Hook::at(leak_value as *const ())
            .redirect(leak_detour as extern "C" fn() -> i32)
            .install()
            .expect("install")
    };
    hook.enable().expect("enable");

    let original = hook.leak();

    // The hook stays installed for the rest of the process, and the leaked
    // pointer still reaches the original.
    assert_eq!(leak_value(), 8);
    assert_eq!(original(), 7);
}

#[inline(never)]
extern "C" fn same_value() -> i32 {
    black_box(0)
}

#[test]
fn target_equal_to_detour_is_refused_and_address_released() {
    // SAFETY: real function; the detour happens to be the same function.
    let result = unsafe {
        Hook::at(same_value as *const ())
            .redirect(same_value as extern "C" fn() -> i32)
            .install()
    };
    assert!(matches!(result, Err(Error::SameAddress { .. })));

    // The failed install must not leave the address reserved.
    extern "C" fn other() -> i32 {
        1
    }
    // SAFETY: real function, shared signature.
    let ok = unsafe {
        Hook::at(same_value as *const ())
            .redirect(other as extern "C" fn() -> i32)
            .install()
    };
    assert!(ok.is_ok());
}

#[inline(never)]
extern "C" fn mt_value() -> i32 {
    black_box(1)
}

extern "C" fn mt_detour() -> i32 {
    2
}

#[test]
fn multithreaded_enable_disable() {
    // SAFETY: real function, shared signature.
    let hook = unsafe {
        Hook::at(mt_value as *const ())
            .redirect(mt_detour as extern "C" fn() -> i32)
            .install()
            .expect("install")
    };

    let stop = Arc::new(AtomicBool::new(false));

    // Worker threads hammer the target while the main thread toggles the hook.
    // With all other threads suspended during each patch, every observed result
    // must be either the original (1) or the detour (2) — never a torn read or
    // a crash from resuming inside a half-written jump.
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let value = black_box(mt_value());
                    assert!(value == 1 || value == 2, "torn result: {value}");
                }
            })
        })
        .collect();

    for _ in 0..150 {
        hook.enable().expect("enable");
        hook.disable().expect("disable");
    }

    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        worker.join().expect("worker thread panicked");
    }
}
