//! Integration tests for register-context injection (x86-64 only).
#![cfg(target_arch = "x86_64")]

use imping_hook::Injection;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[inline(never)]
extern "C" fn two_args(a: u64, b: u64) -> u64 {
    black_box(a).wrapping_add(black_box(b))
}

#[test]
fn inspect_reads_argument_registers() {
    // Win64: first two integer arguments are in rcx and rdx.
    static RCX: AtomicU64 = AtomicU64::new(0);
    static RDX: AtomicU64 = AtomicU64::new(0);

    // SAFETY: `two_args` is a real function whose entry can be relocated; the
    // callback only reads the context.
    let injection = unsafe {
        Injection::at(two_args as *const ())
            .inspect(|ctx| {
                RCX.store(ctx.rcx, Ordering::SeqCst);
                RDX.store(ctx.rdx, Ordering::SeqCst);
            })
            .install()
            .expect("install")
    };

    injection.enable().expect("enable");
    assert_eq!(two_args(0x1111, 0x2222), 0x3333);
    assert_eq!(RCX.load(Ordering::SeqCst), 0x1111);
    assert_eq!(RDX.load(Ordering::SeqCst), 0x2222);
}

#[inline(never)]
extern "C" fn double(x: f64) -> f64 {
    black_box(x) * 2.0
}

#[test]
fn inspect_reads_xmm_registers() {
    // Win64: the first floating-point argument is in xmm0.
    static X: AtomicU64 = AtomicU64::new(0);

    // SAFETY: real function; the callback only reads the context.
    let injection = unsafe {
        Injection::at(double as *const ())
            .inspect(|ctx| X.store(ctx.xmm[0].f64().to_bits(), Ordering::SeqCst))
            .install()
            .expect("install")
    };

    injection.enable().expect("enable");
    assert_eq!(double(3.5), 7.0);
    assert_eq!(f64::from_bits(X.load(Ordering::SeqCst)), 3.5);
}

#[inline(never)]
extern "C" fn add_one(x: u64) -> u64 {
    black_box(x).wrapping_add(1)
}

#[test]
fn modify_changes_a_register_on_the_continue_path() {
    // Overwrite the first argument before the original reads it.
    // SAFETY: real function; the callback writes a register the function uses.
    let injection = unsafe {
        Injection::at(add_one as *const ())
            .modify(|ctx| ctx.rcx = 100)
            .install()
            .expect("install")
    };

    assert_eq!(add_one(5), 6); // before enable: untouched
    injection.enable().expect("enable");
    assert_eq!(add_one(5), 101); // rcx replaced with 100, original adds 1
    injection.disable().expect("disable");
    assert_eq!(add_one(5), 6);
}

#[inline(never)]
extern "C" fn original_value() -> u64 {
    black_box(1)
}

extern "C" fn replacement_value() -> u64 {
    42
}

#[test]
fn modify_rip_redirects_execution() {
    let target = replacement_value as *const () as u64;

    // SAFETY: real function; the callback redirects rip to another function of
    // the same signature, which returns to the original caller.
    let injection = unsafe {
        Injection::at(original_value as *const ())
            .modify(move |ctx| ctx.rip = target)
            .install()
            .expect("install")
    };

    assert_eq!(original_value(), 1);
    injection.enable().expect("enable");
    assert_eq!(original_value(), 42); // redirected, original body skipped
    injection.disable().expect("disable");
    assert_eq!(original_value(), 1);
}

#[inline(never)]
extern "C" fn drop_probe() -> u64 {
    black_box(5)
}

#[test]
fn drop_reverts_injection() {
    static HITS: AtomicU64 = AtomicU64::new(0);
    {
        // SAFETY: real function; the callback only reads the context.
        let injection = unsafe {
            Injection::at(drop_probe as *const ())
                .inspect(|_ctx| {
                    HITS.fetch_add(1, Ordering::SeqCst);
                })
                .install()
                .expect("install")
        };
        injection.enable().expect("enable");
        assert_eq!(drop_probe(), 5);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
    // Dropped, so the callback no longer fires.
    assert_eq!(drop_probe(), 5);
    assert_eq!(HITS.load(Ordering::SeqCst), 1);
}

#[inline(never)]
extern "C" fn mt_probe(x: u64) -> u64 {
    black_box(x).wrapping_mul(2)
}

#[test]
fn multithreaded_inspect() {
    static HITS: AtomicU64 = AtomicU64::new(0);

    // SAFETY: real function; the callback only reads the context and bumps an
    // atomic, so it can run on several threads at once.
    let injection = unsafe {
        Injection::at(mt_probe as *const ())
            .inspect(|ctx| {
                assert_eq!(ctx.rcx, 21);
                HITS.fetch_add(1, Ordering::SeqCst);
            })
            .install()
            .expect("install")
    };
    injection.enable().expect("enable");

    let stop = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicU64::new(0));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            let calls = Arc::clone(&calls);
            thread::spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    assert_eq!(mt_probe(21), 42);
                    n += 1;
                }
                calls.fetch_add(n, Ordering::SeqCst);
            })
        })
        .collect();

    thread::sleep(std::time::Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        worker.join().expect("worker thread panicked");
    }

    // Every call ran the callback exactly once.
    assert_eq!(HITS.load(Ordering::SeqCst), calls.load(Ordering::SeqCst));
    assert!(calls.load(Ordering::SeqCst) > 0);
}

#[inline(never)]
extern "C" fn roundtrip(x: u64) -> u64 {
    black_box(x).wrapping_add(1)
}

#[test]
fn captures_a_value_in_and_reads_observations_out() {
    // Observations come back out through an `Arc`, no static needed.
    let observed: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&observed);
    // Moved into the callback, which writes it to the first argument.
    let forced: u64 = 100;

    // SAFETY: `roundtrip` is a real function whose entry can be relocated; the
    // callback records the argument and overwrites it before the original runs.
    let injection = unsafe {
        Injection::at(roundtrip as *const ())
            .modify(move |ctx| {
                sink.lock().unwrap().push(ctx.rcx); // the original argument
                ctx.rcx = forced;
            })
            .install()
            .expect("install")
    };

    injection.enable().expect("enable");
    assert_eq!(roundtrip(5), 101); // arg forced to 100, original adds 1
    assert_eq!(roundtrip(7), 101);
    injection.disable().expect("disable");

    assert_eq!(*observed.lock().unwrap(), vec![5, 7]);
}
