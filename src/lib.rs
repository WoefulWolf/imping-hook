//! In-process function hooking for the imping modding suite.
//!
//! This crate installs hooks in the running process: typed function detours
//! ([`Hook`]) and raw code injection at arbitrary addresses ([`Injection`]). It
//! depends on nothing else in the suite and can be used on its own.
//!
//! The hard parts — decoding and relocating the displaced instructions,
//! allocating executable memory within reach of the target, and patching code
//! whilst other threads are suspended — are provided by the [`detour`] crate,
//! wrapped behind this crate's own types so the backend can be replaced later.
//!
//! # Typed detours
//!
//! A [`Hook`] redirects a function to another of the same signature, whilst
//! keeping the original callable:
//!
//! ```no_run
//! use imping_hook::Hook;
//!
//! #[inline(never)]
//! extern "C" fn add(a: i32, b: i32) -> i32 { a + b }
//! extern "C" fn sub(a: i32, b: i32) -> i32 { a - b }
//!
//! # fn main() -> imping_hook::Result<()> {
//! // SAFETY: `add` is a real function with the signature below, and `sub`
//! // shares it.
//! let hook = unsafe {
//!     Hook::at(add as *const ())
//!         .redirect(sub as extern "C" fn(i32, i32) -> i32)
//!         .install()?
//! };
//!
//! hook.enable()?;
//! assert_eq!(add(3, 2), 1);
//! assert_eq!(hook.original().call(3, 2), 5);
//! # Ok(())
//! # }
//! ```
//!
//! Enabling, disabling, and dropping a hook suspend all other threads whilst
//! the code is patched, so hooks are safe to toggle in a running, multi-threaded
//! process.

#![warn(missing_docs)]

mod batch;
mod context;
mod error;
mod function;
mod hook;
mod inject;
mod registry;
mod sys;

pub use crate::batch::batch;
pub use crate::context::{Context, Xmm};
pub use crate::error::{Error, OsError, Result};
pub use crate::function::{Function, Original};
pub use crate::hook::{Hook, HookBuilder, HookWith};
pub use crate::inject::{Injection, InjectionBuilder, InjectionWith};

/// The assembler used to author injected code with
/// [`InjectionBuilder::asm`](crate::InjectionBuilder::asm).
///
/// This re-exports [`iced_x86`]'s `code_asm` module — [`CodeAssembler`], the
/// register constants (`rax`, `xmm0`, …), the memory-operand helpers
/// (`qword_ptr`, …) — plus [`IcedError`]. Reference Rust values by passing them
/// as operands, e.g. `a.mov(rax, some_addr)`.
///
/// [`CodeAssembler`]: iced_x86::code_asm::CodeAssembler
/// [`IcedError`]: iced_x86::IcedError
#[cfg(target_arch = "x86_64")]
pub mod asm {
    pub use iced_x86::IcedError;
    pub use iced_x86::code_asm::*;
}
