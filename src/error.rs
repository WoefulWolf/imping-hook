//! The error type returned by hooking operations.

use core::fmt;

/// The result of a hooking operation.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong when installing, enabling, or disabling a hook.
///
/// Every variant that refers to a specific location carries its `address`, so
/// the [`Display`](fmt::Display) message can name it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A hook (detour or injection) is already installed at this address, and
    /// chaining is not supported.
    AlreadyHooked {
        /// The address that is already hooked.
        address: usize,
    },
    /// The target is too small to be patched, and has no usable padding or
    /// hot-patch area.
    NotEnoughSpace {
        /// The address that could not be patched.
        address: usize,
    },
    /// The bytes that would be displaced contain an instruction that cannot be
    /// relocated to the trampoline (e.g. a relative branch out of range).
    UnrelocatableInstruction {
        /// The address of the offending instruction.
        address: usize,
    },
    /// The target does not begin with a valid instruction.
    InvalidInstruction {
        /// The address that could not be decoded.
        address: usize,
    },
    /// No executable memory could be allocated within branch range of the
    /// target.
    NoNearMemory {
        /// The address no nearby memory could be found for.
        address: usize,
    },
    /// The address is not executable memory.
    NotExecutable {
        /// The address that is not executable.
        address: usize,
    },
    /// The target and the detour are the same address.
    SameAddress {
        /// The shared address.
        address: usize,
    },
    /// The code at the address was modified by a third party since the hook was
    /// installed, so it can no longer be toggled safely.
    TargetModified {
        /// The address whose code was modified.
        address: usize,
    },
    /// A thread suspended during a transaction is executing code that cannot be
    /// relocated.
    ThreadNotRelocatable,
    /// An operating system call (memory protection, or thread suspension)
    /// failed.
    Os(OsError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlreadyHooked { address } => {
                write!(f, "address {address:#x} is already hooked")
            }
            Error::NotEnoughSpace { address } => {
                write!(f, "not enough space to patch the target at {address:#x}")
            }
            Error::UnrelocatableInstruction { address } => {
                write!(f, "the instruction at {address:#x} cannot be relocated")
            }
            Error::InvalidInstruction { address } => {
                write!(f, "the target at {address:#x} is not a valid instruction")
            }
            Error::NoNearMemory { address } => {
                write!(
                    f,
                    "no executable memory could be allocated near {address:#x}"
                )
            }
            Error::NotExecutable { address } => {
                write!(f, "the address {address:#x} is not executable")
            }
            Error::SameAddress { address } => {
                write!(f, "the target and detour are the same address {address:#x}")
            }
            Error::TargetModified { address } => {
                write!(f, "the code at {address:#x} was modified by a third party")
            }
            Error::ThreadNotRelocatable => {
                f.write_str("a suspended thread is executing code that cannot be relocated")
            }
            Error::Os(_) => f.write_str("an operating system call failed"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::Os(error) => Some(error),
            _ => None,
        }
    }
}

impl Error {
    /// Maps a [`detour::Error`] to our error, attaching the `address` the
    /// operation concerned (`detour`'s errors do not carry it).
    pub(crate) fn from_detour(error: detour::Error, address: usize) -> Self {
        match error {
            detour::Error::SameAddress => Error::SameAddress { address },
            detour::Error::InvalidInstruction => Error::InvalidInstruction { address },
            detour::Error::PatchAreaTooSmall => Error::NotEnoughSpace { address },
            detour::Error::NotExecutable => Error::NotExecutable { address },
            detour::Error::NoNearbyMemory => Error::NoNearMemory { address },
            detour::Error::UnsupportedInstruction => Error::UnrelocatableInstruction { address },
            detour::Error::TargetModified => Error::TargetModified { address },
            detour::Error::ThreadNotRelocatable => Error::ThreadNotRelocatable,
            detour::Error::Memory(os) => Error::Os(OsError::from_detour(os, "memory protection")),
            detour::Error::Thread(os) => Error::Os(OsError::from_detour(os, "thread suspension")),
            // The remaining variants cannot occur with the exact `detour`
            // version this crate pins: hooks are always initialized at
            // construction (ruling out `NotInitialized` / `AlreadyInitialized`),
            // and on Windows thread suspension is always available (ruling out
            // `ThreadsUnsupported`). The wildcard is required because
            // `detour::Error` is `#[non_exhaustive]`.
            other => unreachable!("detour returned an error that cannot occur here: {other:?}"),
        }
    }
}

/// A failed operating system call (e.g. allocating or protecting memory, or
/// suspending a thread).
///
/// It carries a short description of the operation, and the raw OS error code
/// when one is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsError {
    /// The operating system error code (`GetLastError` on Windows), if known.
    code: Option<i32>,
    /// A short description of the operation that failed.
    context: &'static str,
}

impl OsError {
    /// Returns the operating system error code (`GetLastError` on Windows), if
    /// one was recorded.
    pub fn raw_os_error(&self) -> Option<i32> {
        self.code
    }

    /// Wraps a [`detour::OsError`] with a description of the operation.
    pub(crate) fn from_detour(error: detour::OsError, context: &'static str) -> Self {
        OsError {
            code: error.raw_os_error(),
            context,
        }
    }

    /// Wraps a [`region::Error`] with a description of the operation.
    pub(crate) fn from_region(error: region::Error, context: &'static str) -> Self {
        let code = match error {
            region::Error::SystemCall(code) | region::Error::MachCall(code) => Some(code),
            _ => None,
        };
        OsError { code, context }
    }

    /// Builds an error from the calling thread's last OS error
    /// (`GetLastError`).
    #[cfg(windows)]
    pub(crate) fn last_os_error(context: &'static str) -> Self {
        // SAFETY: `GetLastError` only reads the calling thread's last-error
        // code and has no preconditions.
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        OsError {
            code: Some(code as i32),
            context,
        }
    }
}

impl fmt::Display for OsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(
                f,
                "{} failed: {}",
                self.context,
                std::io::Error::from_raw_os_error(code)
            ),
            None => write!(f, "{} failed", self.context),
        }
    }
}

impl core::error::Error for OsError {}
