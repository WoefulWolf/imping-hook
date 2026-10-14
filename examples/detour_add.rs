//! Detours a function and calls the original through the hook.
//!
//! Run with: `cargo run --example detour_add`

use imping_hook::Hook;

#[inline(never)]
extern "C" fn add(a: i32, b: i32) -> i32 {
    std::hint::black_box(a) + b
}

extern "C" fn sub(a: i32, b: i32) -> i32 {
    a - b
}

fn main() -> imping_hook::Result<()> {
    // SAFETY: `add` is a real function with the signature declared below, and
    // `sub` shares that signature and calling convention.
    let hook = unsafe {
        Hook::at(add as *const ())
            .redirect(sub as extern "C" fn(i32, i32) -> i32)
            .install()?
    };

    println!("before enable: add(3, 2) = {}", add(3, 2));

    hook.enable()?;
    println!("while enabled: add(3, 2) = {}", add(3, 2));
    println!("original via hook: {}", hook.original().call(3, 2));

    hook.disable()?;
    println!("after disable: add(3, 2) = {}", add(3, 2));

    Ok(())
}
