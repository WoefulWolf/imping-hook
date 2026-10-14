//! The only operating-system-specific code in the crate.
//!
//! Kept tiny and `cfg`-gated so other platforms can be added later without
//! touching the rest of the crate.

use crate::error::{Error, OsError, Result};

/// Flushes the instruction cache for `len` bytes at `address`, so a CPU that
/// later executes freshly written code there does not run a stale copy.
///
/// # Safety
///
/// `address` must point to `len` bytes of memory owned by the caller.
#[cfg(windows)]
pub(crate) unsafe fn flush_instruction_cache(address: *const u8, len: usize) -> Result<()> {
    use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: `GetCurrentProcess` returns a pseudo-handle and takes no
    // arguments; `FlushInstructionCache` is given a region the caller owns.
    let ok = unsafe { FlushInstructionCache(GetCurrentProcess(), address.cast(), len) };
    if ok == 0 {
        return Err(Error::Os(OsError::last_os_error(
            "flushing the instruction cache",
        )));
    }
    Ok(())
}

/// On x86 and x86-64 the instruction cache is coherent with data writes, so no
/// explicit flush is required; this is a no-op until a platform that needs one
/// is supported.
#[cfg(not(windows))]
pub(crate) unsafe fn flush_instruction_cache(_address: *const u8, _len: usize) -> Result<()> {
    Ok(())
}
