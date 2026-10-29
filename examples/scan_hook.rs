//! Finds a function by a byte pattern and hooks it.
//!
//! A real mod would write the pattern by hand, from a disassembler. Here it's
//! read from the function itself, so the example runs anywhere.
//!
//! Run with: `cargo run --example scan_hook`

use imping_hook::{Hook, scan};

#[inline(never)]
extern "C" fn add(a: i32, b: i32) -> i32 {
    std::hint::black_box(a).wrapping_mul(0x2F1B_3C4D) ^ b
}

extern "C" fn sub(a: i32, b: i32) -> i32 {
    a - b
}

/// Grows a pattern of `add`'s first bytes until it matches only `add`.
fn pattern_of_add() -> String {
    (8..=64)
        .map(|len| {
            // SAFETY: `add` is followed by more code in this executable.
            let bytes = unsafe { std::slice::from_raw_parts(add as *const u8, len) };
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
    let pattern = pattern_of_add();
    println!("pattern: {pattern}");
    println!(
        "found at {:p}, add is at {:p}",
        scan::find(&pattern)?,
        add as *const ()
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
