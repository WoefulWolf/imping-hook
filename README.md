# imping-hook

In-process function hooking for the imping toolkit: typed detours, register callbacks, and code injection from assembly or raw bytes, at any address. It depends on nothing else in imping.

```toml
[dependencies]
imping-hook = { git = "https://github.com/WoefulWolf/imping-hook" }
```

Detour a function, keeping the original callable:

```rust
use imping_hook::Hook;

#[inline(never)]
extern "C" fn add(a: i32, b: i32) -> i32 { a + b }
extern "C" fn sub(a: i32, b: i32) -> i32 { a - b }

let hook = unsafe {
    Hook::at(add as *const ())
        .redirect(sub as extern "C" fn(i32, i32) -> i32)
        .install()?
};
hook.enable()?;
assert_eq!(add(3, 2), 1); // runs `sub` now
assert_eq!(hook.original().call(3, 2), 5);
```

Read or rewrite the registers at any address, then let the original code carry on:

```rust
use imping_hook::Injection;

// Any instruction will do, e.g. one you found in Ghidra, mid-function.
let addr = (base + 0x12345) as *const ();

let injection = unsafe {
    Injection::at(addr)
        .modify(|ctx| ctx.rcx = 40) // or .inspect(|ctx| println!("rcx = {}", ctx.rcx))
        .install()?
};
injection.enable()?;
```

Or inject your own assembly (or raw machine code with `.code(&bytes)`):

```rust
use imping_hook::asm::{byte_ptr, rax};

let flag = &CALLED as *const AtomicU8 as u64;
// Set `CALLED` every time execution reaches `addr`.
let injection = unsafe {
    Injection::at(addr)
        .asm(move |a| {
            a.push(rax)?;
            a.mov(rax, flag)?;
            a.mov(byte_ptr(rax), 1i32)?;
            a.pop(rax)?;
            Ok(())
        })
        .install()?
};
injection.enable()?;
```

[API docs](https://woefulwolf.github.io/imping-hook/) · Early development, Windows x64 only for now.

If imping helped your project, a mention or link back is appreciated. I'd also love to see what you make with it: share it in [Show and tell](https://github.com/WoefulWolf/imping/discussions/categories/show-and-tell), and it might get featured here!

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

AI assistance was used for parts of this project.
