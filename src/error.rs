//! The error type returned by hooking operations.

use core::fmt;

/// The result of a hooking operation.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong when finding, installing, enabling or disabling
/// a hook.
///
/// Variants about a specific location carry its `address`, and those about a
/// [`scan`](crate::scan) its pattern or module, which the
/// [`Display`](fmt::Display) message names.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A detour or injection is already installed at this address; hooks
    /// aren't chained.
    AlreadyHooked {
        /// The address that is already hooked.
        address: usize,
    },
    /// The target is too small to patch and has no usable padding or hot-patch
    /// area.
    NotEnoughSpace {
        /// The address that could not be patched.
        address: usize,
    },
    /// A displaced instruction can't be relocated to the trampoline, such as a
    /// relative branch that would be out of range.
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
    /// A third party changed the code at the address since the hook was
    /// installed, so it can't be toggled safely.
    TargetModified {
        /// The address whose code was modified.
        address: usize,
    },
    /// A thread suspended for patching is running code that can't be
    /// relocated.
    ThreadNotRelocatable,
    /// The assembly supplied to an injection could not be encoded.
    Assembly {
        /// The address the injection was being built for.
        address: usize,
        /// The assembler's message, prefixed with the instruction's position
        /// when one instruction is invalid.
        reason: String,
    },
    /// An operating system call failed, such as changing memory protection or
    /// suspending a thread.
    Os(OsError),
    /// A [`scan`](crate::scan) pattern can't be parsed, or doesn't spell out the
    /// call that [`follow_call`](crate::HookScan::follow_call) needs.
    InvalidPattern {
        /// The pattern as given.
        pattern: String,
        /// The byte position in `pattern` where it goes wrong.
        position: usize,
    },
    /// A pattern matched nowhere in the module's code.
    PatternNotFound {
        /// The pattern as given.
        pattern: String,
    },
    /// A pattern matched more than once, so it can't tell which place is meant.
    PatternNotUnique {
        /// The pattern as given.
        pattern: String,
        /// How many times it matched.
        matches: usize,
    },
    /// No loaded module has the name a scan was given.
    ModuleNotFound {
        /// The module name as given.
        name: String,
    },
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
            Error::Assembly { address, reason } => {
                write!(
                    f,
                    "the assembly for the injection at {address:#x} could not be encoded: {reason}"
                )
            }
            Error::Os(_) => f.write_str("an operating system call failed"),
            Error::InvalidPattern { pattern, position } => {
                write!(f, "pattern `{pattern}` is invalid at position {position}")
            }
            Error::PatternNotFound { pattern } => {
                write!(f, "pattern `{pattern}` matched nothing")
            }
            Error::PatternNotUnique { pattern, matches } => {
                write!(f, "pattern `{pattern}` matched {matches} places, not one")
            }
            Error::ModuleNotFound { name } => write!(f, "module `{name}` is not loaded"),
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
    /// Maps a [`detour::Error`] to ours, adding the `address` it lacks.
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
            // Can't occur with the pinned detour version: hooks are initialized
            // at construction, and Windows always has thread suspension. The
            // wildcard is needed because `detour::Error` is non-exhaustive.
            other => unreachable!("detour returned an error that cannot occur here: {other:?}"),
        }
    }
}

/// A failed operating system call, such as allocating or protecting memory or
/// suspending a thread.
///
/// Carries a short description of the operation and, when available, the raw
/// OS error code.
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

    /// Builds an error from the calling thread's `GetLastError` code.
    #[cfg(windows)]
    pub(crate) fn last_os_error(context: &'static str) -> Self {
        // SAFETY: `GetLastError` has no preconditions.
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
