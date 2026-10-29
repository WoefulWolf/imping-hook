//! Finds a function by a byte pattern and hooks it.
//!
//! A real mod would write the pattern by hand, from a disassembler. Here it's
//! read from the function itself, so the example runs anywhere.
//!
//! Run with: `cargo run --example scan_hook`

use imping_hook::Hook;
use imping_hook::scan::{self, Pattern};

#[inline(never)]
extern "C" fn add(a: i32, b: i32) -> i32 {
    std::hint::black_box(a).wrapping_mul(0x2F1B_3C4D) ^ b
}

extern "C" fn sub(a: i32, b: i32) -> i32 {
    a - b
}

/// Grows a pattern of the code at `at` until it matches only there.
fn pattern_at(at: *const u8) -> String {
    (8..=64)
        .map(|len| {
            // SAFETY: `at` is inside `add`, which is followed by more code in
            // this executable.
            let bytes = unsafe { std::slice::from_raw_parts(at, len) };
            bytes
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .find(|pattern| scan::find(pattern).is_ok())
        .expect("a unique pattern")
}

fn main() -> imping_hook::Result<()> {
    let pattern = pattern_at(add as *const u8);
    println!("pattern: {pattern}");
    println!(
        "found at {:p}, add is at {:p}",
        scan::find(&pattern)?,
        add as *const ()
    );

    // A pattern from inside `add`, stepped back to its start.
    // SAFETY: `add` is longer than four bytes.
    let inner = pattern_at(unsafe { (add as *const u8).add(4) });
    println!(
        "stepped back to {:p}",
        Pattern::new(&inner).offset(-4).find()?
    );

    // SAFETY: the pattern finds `add`, and `sub` shares its signature.
    let hook = unsafe {
        Hook::scan(&pattern)
            .redirect(sub as extern "C" fn(i32, i32) -> i32)
            .install()?
    };
    hook.enable()?;
    println!("while enabled: add(3, 2) = {}", add(3, 2));
    hook.disable()?;
    println!("after disable: add(3, 2) = {}", add(3, 2));
    Ok(())
}
