//! Reads and then rewrites a function's registers with a register-context
//! injection.
//!
//! Run with: `cargo run --example inspect_registers` (x86-64 only).

#[cfg(target_arch = "x86_64")]
fn main() -> imping_hook::Result<()> {
    use imping_hook::Injection;

    #[inline(never)]
    extern "C" fn compute(a: u64, b: u64) -> u64 {
        std::hint::black_box(a).wrapping_add(std::hint::black_box(b))
    }

    // Win64 passes the first two arguments in rcx and rdx. The block drops the
    // injection, which frees the address for the next one.
    {
        // SAFETY: `compute` is a real function whose entry can be relocated.
        let inspect = unsafe {
            Injection::at(compute as *const ())
                .inspect(|ctx| println!("compute called with rcx={}, rdx={}", ctx.rcx, ctx.rdx))
                .install()?
        };
        inspect.enable()?;
        println!("compute(2, 3) = {}", compute(2, 3));
    }

    // Force the first argument to 40 before the original runs.
    // SAFETY: as above; the callback writes a register the function then reads.
    let modify = unsafe {
        Injection::at(compute as *const ())
            .modify(|ctx| ctx.rcx = 40)
            .install()?
    };
    modify.enable()?;
    println!("compute(2, 3) with rcx forced to 40 = {}", compute(2, 3));
    modify.disable()?;

    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    println!("this example targets x86-64 only");
}
