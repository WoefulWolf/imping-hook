//! Integration tests for raw code injection.
//!
//! The injected machine code is x86-64, so these tests run on that
//! architecture only.
#![cfg(target_arch = "x86_64")]

use imping_hook::{Error, Hook, Injection};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::thread;

/// Builds x86-64 code that stores 1 to `flag_addr` while preserving every
/// register and flag: `push rax; mov rax, flag_addr; mov byte [rax], 1; pop rax`.
fn set_flag_code(flag_addr: u64) -> Vec<u8> {
    let mut code = vec![0x50, 0x48, 0xB8];
    code.extend_from_slice(&flag_addr.to_le_bytes());
    code.extend_from_slice(&[0xC6, 0x00, 0x01, 0x58]);
    code
}

#[inline(never)]
extern "C" fn basic_target(x: i32) -> i32 {
    black_box(x) + 1
}

#[test]
fn injected_code_runs_then_original_continues() {
    static FLAG: AtomicU8 = AtomicU8::new(0);
    let code = set_flag_code(&FLAG as *const AtomicU8 as u64);

    // SAFETY: `basic_target` is a real function whose entry can be relocated,
    // and the injected code preserves all registers and flags it relies on.
    let injection = unsafe {
        Injection::at(basic_target as *const ())
            .code(&code)
            .install()
            .expect("install")
    };

    // Before enabling, the injection has no effect.
    FLAG.store(0, Ordering::SeqCst);
    assert_eq!(basic_target(10), 11);
    assert_eq!(FLAG.load(Ordering::SeqCst), 0);

    // While enabled, the injected code runs and the original still returns.
    injection.enable().expect("enable");
    FLAG.store(0, Ordering::SeqCst);
    assert_eq!(basic_target(10), 11);
    assert_eq!(FLAG.load(Ordering::SeqCst), 1);

    // After disabling, the effect is gone again.
    injection.disable().expect("disable");
    FLAG.store(0, Ordering::SeqCst);
    assert_eq!(basic_target(10), 11);
    assert_eq!(FLAG.load(Ordering::SeqCst), 0);
}

#[inline(never)]
extern "C" fn drop_target(x: i32) -> i32 {
    black_box(x) + 1
}

#[test]
fn drop_reverts_injection() {
    static FLAG: AtomicU8 = AtomicU8::new(0);
    let code = set_flag_code(&FLAG as *const AtomicU8 as u64);
    {
        // SAFETY: real function, ABI-preserving code.
        let injection = unsafe {
            Injection::at(drop_target as *const ())
                .code(&code)
                .install()
                .expect("install")
        };
        injection.enable().expect("enable");
        FLAG.store(0, Ordering::SeqCst);
        assert_eq!(drop_target(10), 11);
        assert_eq!(FLAG.load(Ordering::SeqCst), 1);
    }
    // The guard is dropped; the patch is reverted.
    FLAG.store(0, Ordering::SeqCst);
    assert_eq!(drop_target(10), 11);
    assert_eq!(FLAG.load(Ordering::SeqCst), 0);
}

#[inline(never)]
extern "C" fn shared_target(x: i32) -> i32 {
    black_box(x) + 1
}

#[test]
fn injection_and_detour_share_the_address_registry() {
    static FLAG: AtomicU8 = AtomicU8::new(0);
    let code = set_flag_code(&FLAG as *const AtomicU8 as u64);

    // SAFETY: real function, ABI-preserving code.
    let injection = unsafe {
        Injection::at(shared_target as *const ())
            .code(&code)
            .install()
            .expect("install")
    };

    // A detour on the same address is refused while the injection holds it.
    extern "C" fn replacement(_: i32) -> i32 {
        0
    }
    // SAFETY: real function, shared signature.
    let detour = unsafe {
        Hook::at(shared_target as *const ())
            .redirect(replacement as extern "C" fn(i32) -> i32)
            .install()
    };
    assert!(matches!(detour, Err(Error::AlreadyHooked { .. })));

    drop(injection);

    // Once the injection is gone, the address is free again.
    // SAFETY: real function, shared signature.
    let detour = unsafe {
        Hook::at(shared_target as *const ())
            .redirect(replacement as extern "C" fn(i32) -> i32)
            .install()
    };
    assert!(detour.is_ok());
}

#[inline(never)]
extern "C" fn mt_target(x: i32) -> i32 {
    black_box(x) + 1
}

#[test]
fn multithreaded_enable_disable() {
    static FLAG: AtomicU8 = AtomicU8::new(0);
    let code = set_flag_code(&FLAG as *const AtomicU8 as u64);

    // SAFETY: real function, ABI-preserving code.
    let injection = unsafe {
        Injection::at(mt_target as *const ())
            .code(&code)
            .install()
            .expect("install")
    };

    let stop = Arc::new(AtomicBool::new(false));

    // Workers call the target while the main thread toggles the injection.
    // Every call must return the original result and never crash, whether or
    // not the injection is enabled at that instant.
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    assert_eq!(black_box(mt_target(10)), 11);
                }
            })
        })
        .collect();

    for _ in 0..150 {
        injection.enable().expect("enable");
        injection.disable().expect("disable");
    }

    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        worker.join().expect("worker thread panicked");
    }
}
