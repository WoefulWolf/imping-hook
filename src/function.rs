//! The trait describing function signatures that can be hooked.

mod sealed {
    /// Prevents [`Function`](super::Function) from being implemented outside
    /// this crate.
    pub trait Sealed {}

    impl<F: detour::Function> Sealed for F {}
}

/// A function pointer type that can be a [`Hook`](crate::Hook) target and
/// detour.
///
/// Implemented for safe and `unsafe` function pointers with up to 14 arguments
/// in every calling convention the platform has, such as `extern "C"`,
/// `extern "system"`, and on x86 `extern "fastcall"` and `extern "thiscall"`.
/// Signatures with borrows, such as `fn(&str)`, aren't supported. The trait is
/// sealed.
pub trait Function: sealed::Sealed + detour::Function {}

impl<F: detour::Function> Function for F {}

/// The original, unhooked function of a [`Hook`](crate::Hook), borrowed from
/// it.
///
/// Its `call` method takes the hooked function's arguments and is `unsafe` when
/// the signature is. It can't outlive the hook, so it never runs freed
/// trampoline memory.
pub use detour::Original;
