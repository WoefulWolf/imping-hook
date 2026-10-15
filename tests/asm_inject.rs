//! Integration tests for assembling injected code with `asm` (x86-64 only).
#![cfg(target_arch = "x86_64")]

use imping_hook::asm::{byte_ptr, rax};
use imping_hook::{Error, Injection};
use std::hint::black_box;
use std::sync::atomic::{AtomicU8, Ordering};

#[inline(never)]
extern "C" fn add_one(x: u64) -> u64 {
    black_box(x).wrapping_add(1)
}

#[test]
fn asm_references_a_rust_value_and_original_continues() {
    static FLAG: AtomicU8 = AtomicU8::new(0);
    let flag_addr = &FLAG as *const AtomicU8 as u64;

    // push rax; mov rax, <FLAG addr>; mov byte [rax], 1; pop rax.
    // Preserves rax and the flags, and touches no argument register, so the
    // original function runs unchanged while the flag records that we ran.
    // SAFETY: `add_one` is a real function whose entry can be relocated, and the
    // assembly preserves every register and flag it relies on.
    let injection = unsafe {
        Injection::at(add_one as *const ())
            .asm(move |a| {
                a.push(rax)?;
                a.mov(rax, flag_addr)?;
                a.mov(byte_ptr(rax), 1i32)?;
                a.pop(rax)?;
                Ok(())
            })
            .install()
            .expect("install")
    };

    FLAG.store(0, Ordering::SeqCst);
    assert_eq!(add_one(5), 6);
    assert_eq!(FLAG.load(Ordering::SeqCst), 0); // disabled: no effect

    injection.enable().expect("enable");
    FLAG.store(0, Ordering::SeqCst);
    assert_eq!(add_one(5), 6); // original still runs
    assert_eq!(FLAG.load(Ordering::SeqCst), 1); // injected asm ran

    injection.disable().expect("disable");
    FLAG.store(0, Ordering::SeqCst);
    assert_eq!(add_one(5), 6);
    assert_eq!(FLAG.load(Ordering::SeqCst), 0);
}

#[inline(never)]
extern "C" fn double(x: f64) -> f64 {
    black_box(x) * 2.0
}

#[test]
fn asm_injection_is_transparent_to_a_float_function() {
    static FLAG: AtomicU8 = AtomicU8::new(0);
    let flag_addr = &FLAG as *const AtomicU8 as u64;

    // SAFETY: real function; the asm preserves rax/flags and leaves xmm alone.
    let injection = unsafe {
        Injection::at(double as *const ())
            .asm(move |a| {
                a.push(rax)?;
                a.mov(rax, flag_addr)?;
                a.mov(byte_ptr(rax), 1i32)?;
                a.pop(rax)?;
                Ok(())
            })
            .install()
            .expect("install")
    };

    injection.enable().expect("enable");
    FLAG.store(0, Ordering::SeqCst);
    assert_eq!(double(3.5), 7.0); // xmm path undisturbed
    assert_eq!(FLAG.load(Ordering::SeqCst), 1);
}

#[inline(never)]
extern "C" fn invalid_target() -> u64 {
    black_box(0)
}

#[test]
fn asm_that_cannot_be_encoded_is_reported() {
    // A byte store with an immediate that does not fit in a byte cannot be
    // encoded, so assembling fails.
    // SAFETY: the target is never patched, since assembly fails first.
    let result = unsafe {
        Injection::at(invalid_target as *const ())
            .asm(|a| {
                a.mov(byte_ptr(rax), 0x1234i32)?;
                Ok(())
            })
            .install()
    };
    match result {
        Err(Error::Assembly { reason, .. }) => {
            // The iced diagnostic is carried through, prefixed with the position.
            assert!(
                reason.starts_with("instruction 0:"),
                "reason was {reason:?}"
            );
            assert!(reason.len() > "instruction 0:".len());
        }
        other => panic!("expected an assembly error, got {other:?}"),
    }

    // The failed install must not leave the address reserved.
    static FLAG: AtomicU8 = AtomicU8::new(0);
    let flag_addr = &FLAG as *const AtomicU8 as u64;
    // SAFETY: real function; simple flag-setting asm.
    let ok = unsafe {
        Injection::at(invalid_target as *const ())
            .asm(move |a| {
                a.push(rax)?;
                a.mov(rax, flag_addr)?;
                a.mov(byte_ptr(rax), 1i32)?;
                a.pop(rax)?;
                Ok(())
            })
            .install()
    };
    assert!(ok.is_ok());
}
