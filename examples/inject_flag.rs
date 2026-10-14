//! Injects machine code at a function's entry that sets a flag, then lets the
//! original function run.
//!
//! Run with: `cargo run --example inject_flag` (x86-64 only).

#[cfg(target_arch = "x86_64")]
fn main() -> imping_hook::Result<()> {
    use imping_hook::Injection;
    use std::sync::atomic::{AtomicU8, Ordering};

    static FLAG: AtomicU8 = AtomicU8::new(0);

    #[inline(never)]
    extern "C" fn target(x: i32) -> i32 {
        std::hint::black_box(x) + 1
    }

    // Machine code (x86-64) that sets FLAG to 1 without disturbing the original
    // function: save rax, store 1 to FLAG's address, restore rax. `mov` and
    // push/pop leave the flags untouched, and no argument register is touched.
    let flag_addr = &FLAG as *const AtomicU8 as u64;
    let mut code = vec![0x50, 0x48, 0xB8]; // push rax; mov rax, imm64
    code.extend_from_slice(&flag_addr.to_le_bytes());
    code.extend_from_slice(&[0xC6, 0x00, 0x01, 0x58]); // mov byte [rax], 1; pop rax

    // SAFETY: `target` is a real function whose entry can be relocated, and the
    // injected code preserves every register and flag the function relies on.
    let injection = unsafe { Injection::at(target as *const ()).code(&code).install()? };

    println!(
        "before enable: target(10) = {}, flag = {}",
        target(10),
        FLAG.load(Ordering::SeqCst)
    );

    injection.enable()?;
    let result = target(10);
    println!(
        "while enabled: target(10) = {result}, flag = {}",
        FLAG.load(Ordering::SeqCst)
    );

    injection.disable()?;
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    println!("this example targets x86-64 only");
}
