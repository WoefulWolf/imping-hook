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

/// Returns the base address of a loaded module by name, or of the main module
/// for `None`.
#[cfg(windows)]
pub(crate) fn module_base(name: Option<&str>) -> Option<*const u8> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

    // An interior NUL would silently shorten the name.
    if name.is_some_and(|name| name.contains('\0')) {
        return None;
    }
    let wide: Option<Vec<u16>> = name.map(|name| name.encode_utf16().chain([0]).collect());
    let name = wide
        .as_ref()
        .map_or(core::ptr::null(), |wide| wide.as_ptr());
    // SAFETY: `name` is null or a NUL-terminated UTF-16 string that outlives the
    // call.
    let handle = unsafe { GetModuleHandleW(name) };
    (!handle.is_null()).then_some(handle as *const u8)
}

/// Finds no modules: the scanner only reads Windows (PE) images so far.
#[cfg(not(windows))]
pub(crate) fn module_base(_name: Option<&str>) -> Option<*const u8> {
    None
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
