//! Injects code written as assembly at a function's entry, referencing a Rust
//! value, then letting the original run.
//!
//! Run with: `cargo run --example asm_inject` (x86-64 only).

#[cfg(target_arch = "x86_64")]
fn main() -> imping_hook::Result<()> {
    use imping_hook::Injection;
    use imping_hook::asm::{byte_ptr, rax};
    use std::sync::atomic::{AtomicU8, Ordering};

    static CALLED: AtomicU8 = AtomicU8::new(0);

    #[inline(never)]
    extern "C" fn target(x: i32) -> i32 {
        std::hint::black_box(x) + 1
    }

    // The address of a Rust value, embedded into the assembly as an immediate.
    let flag = &CALLED as *const AtomicU8 as u64;

    // SAFETY: `target` is a real function whose entry can be relocated; the
    // assembly preserves every register and flag the function relies on.
    let injection = unsafe {
        Injection::at(target as *const ())
            .asm(move |a| {
                a.push(rax)?; // save rax
                a.mov(rax, flag)?; // rax = &CALLED
                a.mov(byte_ptr(rax), 1i32)?; // CALLED = 1
                a.pop(rax)?; // restore rax
                Ok(())
            })
            .install()?
    };

    println!(
        "before enable: target(10) = {}, called = {}",
        target(10),
        CALLED.load(Ordering::SeqCst)
    );

    injection.enable()?;
    let result = target(10);
    println!(
        "while enabled: target(10) = {result}, called = {}",
        CALLED.load(Ordering::SeqCst)
    );

    injection.disable()?;
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    println!("this example targets x86-64 only");
}
