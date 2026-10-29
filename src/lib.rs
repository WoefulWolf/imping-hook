//! In-process function hooking for the imping toolkit.
//!
//! Installs typed function detours and code injections at arbitrary addresses
//! in the running process, and depends on nothing else in imping.
//! Relocation, near-memory allocation and thread-safe patching come from the
//! [`detour`] crate, wrapped behind this crate's types.
//!
//! # Examples
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
//! # Main items
//!
//! - [`Hook`] redirects a function to another of the same signature and keeps
//!   the original callable. Its docs cover threads, batches and dropping.
//! - [`Injection`] runs machine code, assembly or a register callback at an
//!   address, then the original code.
//! - [`scan`] finds code by a byte pattern; [`Hook::scan`] and
//!   [`Injection::scan`] patch what it finds.
//! - [`batch`] applies many enables and disables with one thread suspension.
//! - [`Context`] holds the registers a register callback sees.
//! - [`Error`] lists everything that can fail.

#![warn(missing_docs)]

mod batch;
mod context;
mod error;
mod function;
mod hook;
mod inject;
mod registry;
pub mod scan;
mod sys;

pub use crate::batch::batch;
pub use crate::context::{Context, Xmm};
pub use crate::error::{Error, OsError, Result};
pub use crate::function::{Function, Original};
pub use crate::hook::{Hook, HookBuilder, HookScan, HookWith};
pub use crate::inject::{Injection, InjectionBuilder, InjectionScan, InjectionWith};

/// Re-exports the assembler used by
/// [`InjectionBuilder::asm`](crate::InjectionBuilder::asm).
///
/// This is [`iced_x86`]'s `code_asm` module ([`CodeAssembler`], register
/// constants such as `rax` and `xmm0`, operand helpers such as `qword_ptr`)
/// plus [`IcedError`].
///
/// [`CodeAssembler`]: iced_x86::code_asm::CodeAssembler
/// [`IcedError`]: iced_x86::IcedError
#[cfg(target_arch = "x86_64")]
pub mod asm {
    pub use iced_x86::IcedError;
    pub use iced_x86::code_asm::*;
}
