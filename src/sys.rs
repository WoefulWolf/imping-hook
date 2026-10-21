//! OS-specific helpers, kept small and `cfg`-gated.

use crate::error::{Error, OsError, Result};

/// Flushes the instruction cache for `len` bytes at `address`, so freshly
/// written code there doesn't run from a stale copy.
///
/// # Safety
///
/// `address` must point to `len` bytes of memory the caller owns.
#[cfg(windows)]
pub(crate) unsafe fn flush_instruction_cache(address: *const u8, len: usize) -> Result<()> {
    use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: `GetCurrentProcess` returns a pseudo-handle, and the region
    // belongs to the caller.
    let ok = unsafe { FlushInstructionCache(GetCurrentProcess(), address.cast(), len) };
    if ok == 0 {
        return Err(Error::Os(OsError::last_os_error(
            "flushing the instruction cache",
        )));
    }
    Ok(())
}

/// Does nothing, since x86 and x86-64 keep the instruction cache coherent with
/// data writes.
///
/// # Safety
///
/// `address` must point to `len` bytes of memory the caller owns.
#[cfg(not(windows))]
pub(crate) unsafe fn flush_instruction_cache(_address: *const u8, _len: usize) -> Result<()> {
    Ok(())
}
