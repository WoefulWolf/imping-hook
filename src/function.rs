//! The trait describing function signatures that can be hooked.

mod sealed {
    /// Prevents [`Function`](super::Function) from being implemented outside
    /// this crate.
    pub trait Sealed {}

    impl<F: detour::Function> Sealed for F {}
}

/// A function pointer whose signature can be used as a [`Hook`](crate::Hook)
/// target and detour.
///
/// It is implemented for all function-pointer types the backend supports:
/// every calling convention available on the platform (e.g. `extern "C"`,
/// `extern "system"`, and, on x86, `extern "fastcall"` and
/// `extern "thiscall"`), with up to 14 arguments, in both `unsafe` and safe
/// form.
///
/// Signatures that borrow their arguments or return values (e.g. `fn(&str)`)
/// are not supported, since game functions use C-compatible ABIs over plain
/// data. This trait is sealed and cannot be implemented outside this crate.
pub trait Function: sealed::Sealed + detour::Function {}

impl<F: detour::Function> Function for F {}

/// The original, un-hooked function of a [`Hook`](crate::Hook), borrowed from
/// it.
///
/// Returned by [`Hook::original`](crate::Hook::original). Its `call` method
/// takes the same arguments as the hooked function, and is `unsafe` whenever
/// the signature is an `unsafe` function. It cannot outlive the hook it was
/// borrowed from, so calling it can never use freed trampoline memory.
pub use detour::Original;
