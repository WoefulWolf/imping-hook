//! Enables several injections in one batch, so other threads are suspended
//! once rather than once per patch, then disables one without suspending
//! any thread.
//!
//! Run with: `cargo run --example batch_enable`

use imping_hook::Injection;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

static CALLS: AtomicUsize = AtomicUsize::new(0);

#[inline(never)]
extern "C" fn first(x: u64) -> u64 {
    black_box(x) + 1
}

#[inline(never)]
extern "C" fn second(x: u64) -> u64 {
    black_box(x) * 2
}

fn main() -> imping_hook::Result<()> {
    let mut injections = Vec::new();
    for target in [first as *const (), second as *const ()] {
        let builder = Injection::at(target).modify(|_| {
            CALLS.fetch_add(1, Ordering::Relaxed);
        });
        // SAFETY: both targets are real functions, and the stub saves and
        // restores every register around the callback.
        injections.push(unsafe { builder.install() }?);
    }

    let failed = imping_hook::batch(|| {
        for injection in &injections {
            injection.enable().expect("queued until the batch ends");
        }
    });
    assert!(failed.is_empty(), "{failed:?}");
    println!("first(1) = {}, second(2) = {}", first(1), second(2));
    println!("injected code ran {} times", CALLS.load(Ordering::Relaxed));

    // SAFETY: this program has no other thread that could be running `first`.
    unsafe { injections[0].disable_unsuspended() }?;
    first(1);
    println!(
        "after disabling one: {} calls",
        CALLS.load(Ordering::Relaxed)
    );
    Ok(())
}
