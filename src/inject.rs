//! Raw code injection: run the caller's own machine code at an arbitrary
//! address, then the instructions it displaced, then continue.

use crate::error::{Error, OsError, Result};
use crate::registry;
use crate::sys;
use core::mem::ManuallyDrop;
use core::ptr;
use region::Protection;

/// The length of the absolute jump appended to the stub, per architecture.
#[cfg(target_arch = "x86_64")]
const ABS_JUMP_LEN: usize = 14;
#[cfg(target_arch = "x86")]
const ABS_JUMP_LEN: usize = 6;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("imping-hook code injection supports only x86 and x86-64");

/// Builds an absolute jump to `target` that clobbers no registers or flags.
///
/// On x86-64 this is `jmp qword ptr [rip+0]` followed by the 64-bit address; on
/// x86 it is `push imm32; ret`, which is stack- and flag-neutral.
fn absolute_jump(target: usize) -> [u8; ABS_JUMP_LEN] {
    let mut bytes = [0u8; ABS_JUMP_LEN];
    #[cfg(target_arch = "x86_64")]
    {
        bytes[0] = 0xFF;
        bytes[1] = 0x25; // jmp qword ptr [rip+0]; disp32 == 0 leaves bytes[2..6] zero
        bytes[6..14].copy_from_slice(&(target as u64).to_le_bytes());
    }
    #[cfg(target_arch = "x86")]
    {
        bytes[0] = 0x68; // push imm32
        bytes[1..5].copy_from_slice(&(target as u32).to_le_bytes());
        bytes[5] = 0xC3; // ret
    }
    bytes
}

/// A block of injected machine code, and the RAII guard that owns it.
///
/// When enabled, reaching `target` runs the injected code, then the original
/// instructions that were displaced to make room for the patch, then
/// continues after the patched bytes. Build one with [`Injection::at`].
///
/// The injected code is responsible for honouring the platform ABI, since this
/// crate cannot inspect it. On Windows x64 that means preserving every register
/// and flag the surrounding function relies on, reserving 32 bytes of shadow
/// space and keeping 16-byte stack alignment before any `call`, and not
/// branching into the displaced bytes.
///
/// # Thread safety and dropping
///
/// Enabling, disabling, and dropping an `Injection` suspend every other thread
/// whilst the code is patched, exactly like [`Hook`](crate::Hook). On drop the
/// patch is reverted and the stub freed; if it cannot be reverted, the stub is
/// leaked so the target never jumps into freed memory. [`leak`](Self::leak)
/// keeps an injection installed for the rest of the process.
pub struct Injection {
    inner: detour::RawDetour,
    // Freed manually, and only once the target no longer jumps to it.
    stub: ManuallyDrop<region::Allocation>,
    target: usize,
}

// `Injection` is `Send + Sync`: `detour::RawDetour` is both, the allocation is
// just owned memory, and the remaining field is a plain address.
// SAFETY: the stub memory is only mutated during construction (before it is
// shared) and freed during drop; all code modification is serialized by the
// backend's global patch lock.
unsafe impl Send for Injection {}
// SAFETY: see above; `&Injection` only exposes locked operations and atomics.
unsafe impl Sync for Injection {}

/// The entry point for building an injection, returned handle-free so
/// `Injection::at(..)` reads cleanly.
impl Injection {
    /// Begins building an injection at `target`.
    ///
    /// `target` is the address at which the injected code will run, as resolved
    /// from a module base. Nothing is patched until
    /// [`install`](InjectionWith::install) is called.
    pub fn at(target: *const ()) -> InjectionBuilder {
        InjectionBuilder { target }
    }

    /// Enables the injection.
    ///
    /// All other threads are suspended whilst the code is patched (see the
    /// [type-level note](Self#thread-safety-and-dropping)). Enabling an
    /// already-enabled injection does nothing.
    pub fn enable(&self) -> Result<()> {
        self.toggle(true)
    }

    /// Disables the injection, restoring the original code.
    ///
    /// All other threads are suspended whilst the code is restored. Disabling
    /// an already-disabled injection does nothing.
    pub fn disable(&self) -> Result<()> {
        self.toggle(false)
    }

    /// Returns whether the injection is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Consumes the injection and keeps it installed for the rest of the
    /// process.
    ///
    /// The injection is left in whatever state it is currently in, so call
    /// [`enable`](Self::enable) first if it should stay active. The target's
    /// address remains reserved, so it cannot be hooked again.
    pub fn leak(self) {
        core::mem::forget(self);
    }

    /// Enables or disables the injection within a transaction that suspends all
    /// other threads.
    fn toggle(&self, enable: bool) -> Result<()> {
        let mut transaction = detour::Transaction::new();
        if enable {
            transaction.enable(&self.inner);
        } else {
            transaction.disable(&self.inner);
        }
        // SAFETY: `Threads::All` suspends every other thread of the process, so
        // none can be executing the patched bytes whilst they are written, and
        // any thread stopped inside them is relocated by the transaction. The
        // only unsuspended thread is the caller, which must not be executing
        // the patched bytes itself.
        unsafe { transaction.commit(detour::Threads::All) }
            .map_err(|error| Error::from_detour(error, self.target))
    }

    /// Builds the stub and the backing detour. Reserving the address and
    /// releasing it on failure is the caller's responsibility.
    ///
    /// # Safety
    ///
    /// See [`InjectionWith::install`].
    unsafe fn build(target: *const (), code: &[u8]) -> Result<Injection> {
        let address = target as usize;
        let stub_len = code.len() + ABS_JUMP_LEN;

        // Allocate the stub read-write first.
        let mut stub = region::alloc(stub_len, Protection::READ_WRITE).map_err(|error| {
            Error::Os(OsError::from_region(error, "allocating the injection stub"))
        })?;
        let stub_ptr = stub.as_mut_ptr::<u8>();
        let stub_size = stub.len();

        // Make it executable so the backend accepts it as the detour target.
        // SAFETY: `stub_ptr`/`stub_size` describe the allocation just created.
        unsafe { region::protect(stub_ptr, stub_size, Protection::READ_EXECUTE) }.map_err(
            |error| Error::Os(OsError::from_region(error, "protecting the injection stub")),
        )?;

        // Create the disabled detour: reaching `target` will jump to the stub.
        // The backend relocates the displaced instructions into a trampoline.
        // SAFETY: forwarded — `target` is executable code the caller vouches
        // for; the stub is executable and distinct from the target.
        let inner = unsafe { detour::RawDetour::new(target, stub_ptr.cast()) }
            .map_err(|error| Error::from_detour(error, address))?;
        let trampoline = inner.trampoline() as usize;

        // Write the stub: the caller's code, then an absolute jump to the
        // trampoline (which runs the displaced originals and continues).
        // SAFETY: reverting to read-write the allocation we own.
        unsafe { region::protect(stub_ptr, stub_size, Protection::READ_WRITE) }.map_err(
            |error| Error::Os(OsError::from_region(error, "protecting the injection stub")),
        )?;
        let jump = absolute_jump(trampoline);
        // SAFETY: `stub_ptr` owns `stub_size >= code.len() + jump.len()` bytes,
        // now writable, and the source slices are disjoint from it.
        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), stub_ptr, code.len());
            ptr::copy_nonoverlapping(jump.as_ptr(), stub_ptr.add(code.len()), jump.len());
        }
        // SAFETY: restoring execute protection on the allocation we own.
        unsafe { region::protect(stub_ptr, stub_size, Protection::READ_EXECUTE) }.map_err(
            |error| Error::Os(OsError::from_region(error, "protecting the injection stub")),
        )?;

        // SAFETY: the stub spans `stub_size` bytes of memory we own.
        unsafe { sys::flush_instruction_cache(stub_ptr, stub_size)? };

        Ok(Injection {
            inner,
            stub: ManuallyDrop::new(stub),
            target: address,
        })
    }
}

impl Drop for Injection {
    fn drop(&mut self) {
        // Revert the patch through a transaction so no thread resumes mid-patch.
        // Only free the stub if the target was restored; otherwise it may still
        // jump to the stub, so the stub is leaked and the address stays reserved
        // (the backend likewise leaks its own generated code on failure).
        if self.toggle(false).is_ok() {
            registry::release(self.target);
            // SAFETY: the target no longer jumps to the stub, and the stub is
            // never used again, so freeing it is safe.
            unsafe { ManuallyDrop::drop(&mut self.stub) };
        }
    }
}

impl core::fmt::Debug for Injection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Injection")
            .field("target", &(self.target as *const ()))
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

/// An injection builder holding the target address, returned by
/// [`Injection::at`].
#[must_use = "an injection builder does nothing until `code` and `install` are called"]
pub struct InjectionBuilder {
    target: *const (),
}

impl InjectionBuilder {
    /// Sets the machine code to run at the target. The bytes are copied into
    /// the stub, so the slice need not outlive this call.
    pub fn code(self, code: &[u8]) -> InjectionWith {
        InjectionWith {
            target: self.target,
            code: code.to_vec(),
        }
    }
}

/// An injection builder holding the target and code, returned by
/// [`InjectionBuilder::code`]. Call [`install`](Self::install) to patch the
/// target.
#[must_use = "an injection builder does nothing until `install` is called"]
pub struct InjectionWith {
    target: *const (),
    code: Vec<u8>,
}

impl InjectionWith {
    /// Installs the injection, disabled. Enable it with [`Injection::enable`].
    ///
    /// Fails with [`Error::AlreadyHooked`] if the target address is already
    /// hooked by another injection or detour.
    ///
    /// # Safety
    ///
    /// - `target` must point to executable code whose first bytes can be
    ///   relocated (as for any inline patch), and which it is valid to resume
    ///   after the injected code runs.
    /// - The injected code must be valid machine code for the current
    ///   architecture and must honour the platform ABI: preserve every register
    ///   and flag the surrounding function relies on, keep the stack balanced
    ///   and aligned (reserving shadow space before any `call` on Windows x64),
    ///   and not branch into the displaced bytes.
    pub unsafe fn install(self) -> Result<Injection> {
        let address = self.target as usize;

        // Reserve the address first, so a second hook on it is refused.
        if !registry::claim(address) {
            return Err(Error::AlreadyHooked { address });
        }

        // SAFETY: forwarded from the caller.
        match unsafe { Injection::build(self.target, &self.code) } {
            Ok(injection) => Ok(injection),
            Err(error) => {
                registry::release(address);
                Err(error)
            }
        }
    }
}
