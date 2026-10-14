//! Typed function detours: redirect a function to another of the same
//! signature, whilst keeping the original callable.

use crate::error::{Error, Result};
use crate::function::Function;
use crate::registry;

/// A typed function detour, and the RAII guard that owns it.
///
/// A `Hook` redirects a *target* function to a *detour* of the same signature
/// `F`. Whilst it is enabled, callers of the target run the detour instead; the
/// original remains callable through [`original`](Self::original). Build one
/// with [`Hook::at`].
///
/// # Thread safety
///
/// [`enable`](Self::enable) and [`disable`](Self::disable) are safe: they
/// suspend every other thread of the process whilst the code is patched, and
/// move any thread stopped within the patched bytes to the equivalent location,
/// so no thread can resume in the middle of a half-written jump. The one
/// obligation left to the caller is not to enable or disable a hook from within
/// its own target on the *calling* thread.
///
/// # Dropping
///
/// When a `Hook` is dropped it is disabled (again suspending other threads) and
/// its generated code is released. If it cannot be disabled — for instance
/// because a third party modified the target's bytes — the generated code is
/// leaked instead, so the target never jumps into freed memory. Use
/// [`leak`](Self::leak) to keep a hook installed for the rest of the process on
/// purpose.
///
/// # Example
///
/// ```no_run
/// use imping_hook::Hook;
///
/// #[inline(never)]
/// extern "C" fn add(a: i32, b: i32) -> i32 { a + b }
/// extern "C" fn sub(a: i32, b: i32) -> i32 { a - b }
///
/// # fn main() -> imping_hook::Result<()> {
/// // SAFETY: `add` is a real function with the signature below, and `sub`
/// // shares it.
/// let hook = unsafe {
///     Hook::at(add as *const ())
///         .redirect(sub as extern "C" fn(i32, i32) -> i32)
///         .install()?
/// };
///
/// assert_eq!(add(3, 2), 5);
/// hook.enable()?;
/// assert_eq!(add(3, 2), 1);
/// assert_eq!(hook.original().call(3, 2), 5);
/// hook.disable()?;
/// assert_eq!(add(3, 2), 5);
/// # Ok(())
/// # }
/// ```
pub struct Hook<F: Function = fn()> {
    inner: detour::TypedDetour<F>,
    target: usize,
}

/// The entry point for building a hook. Kept in its own non-generic `impl` so
/// `Hook::at(..)` needs no turbofish; the real signature `F` is fixed later by
/// [`HookBuilder::redirect`].
impl Hook {
    /// Begins building a hook of the function at `target`.
    ///
    /// `target` is the address of the function to hook, as resolved from a
    /// module base. The hook is not created until [`install`](HookWith::install)
    /// is called.
    pub fn at(target: *const ()) -> HookBuilder {
        HookBuilder { target }
    }
}

// `Hook<F>` is automatically `Send + Sync`: `detour::TypedDetour` is both, and
// the only other field is a plain address.
impl<F: Function> Hook<F> {
    /// Enables the hook, redirecting the target to the detour.
    ///
    /// All other threads are suspended whilst the code is patched (see the
    /// [type-level note](Self#thread-safety)). Enabling an already-enabled hook
    /// does nothing.
    pub fn enable(&self) -> Result<()> {
        self.toggle(true)
    }

    /// Disables the hook, restoring the original function.
    ///
    /// All other threads are suspended whilst the code is restored (see the
    /// [type-level note](Self#thread-safety)). Disabling an already-disabled
    /// hook does nothing.
    pub fn disable(&self) -> Result<()> {
        self.toggle(false)
    }

    /// Returns whether the hook is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Returns the original, un-hooked function, borrowed from the hook.
    ///
    /// It can be called regardless of whether the hook is enabled, through its
    /// `call` method, which takes the same arguments as the function and is
    /// `unsafe` if the function is. The borrow prevents it from outliving the
    /// hook, so it can never call into released trampoline memory.
    pub fn original(&self) -> F::Original<'_> {
        self.inner.original()
    }

    /// Returns the trampoline — a pointer to the original function that is not
    /// tied to the hook's lifetime.
    ///
    /// Prefer [`original`](Self::original); use this only when the original must
    /// be stored or passed somewhere that outlives a borrow.
    ///
    /// # Safety
    ///
    /// The returned function must not be called after the hook is dropped. Use
    /// [`leak`](Self::leak) if it must remain callable for the rest of the
    /// process.
    pub unsafe fn trampoline(&self) -> F {
        // SAFETY: Forwarded from the caller.
        unsafe { self.inner.trampoline() }
    }

    /// Consumes the hook and keeps it installed for the rest of the process,
    /// returning a `'static` callable to the original function.
    ///
    /// The hook is left in whatever state it is currently in, so call
    /// [`enable`](Self::enable) first if it should stay active. The target's
    /// address remains reserved, so it cannot be hooked again.
    pub fn leak(self) -> F {
        // SAFETY: `self` is immediately forgotten, so the detour is never
        // dropped and its trampoline lives for the rest of the process. The
        // returned function therefore remains valid for `'static`.
        let original = unsafe { self.inner.trampoline() };
        core::mem::forget(self);
        original
    }

    /// Enables or disables the hook within a transaction that suspends all
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
        // only unsuspended thread is the caller, which must not be executing the
        // target's prolog itself (documented on `enable`/`disable`).
        unsafe { transaction.commit(detour::Threads::All) }
            .map_err(|error| Error::from_detour(error, self.target))
    }
}

impl<F: Function> Drop for Hook<F> {
    fn drop(&mut self) {
        // Disable through a transaction so no thread resumes mid-patch. Only
        // release the address if the target was restored; if it could not be,
        // its code is still patched (and `detour` leaks the generated code), so
        // the address stays reserved.
        if self.toggle(false).is_ok() {
            registry::release(self.target);
        }
    }
}

impl<F: Function> core::fmt::Debug for Hook<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hook")
            .field("target", &(self.target as *const ()))
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

/// A hook builder holding the target address, returned by [`Hook::at`].
#[must_use = "a hook builder does nothing until `redirect` and `install` are called"]
pub struct HookBuilder {
    target: *const (),
}

impl HookBuilder {
    /// Sets the `detour` the target will be redirected to, fixing the hook's
    /// signature `F` to that of the detour.
    pub fn redirect<F: Function>(self, detour: F) -> HookWith<F> {
        HookWith {
            target: self.target,
            detour,
        }
    }
}

/// A hook builder holding the target and detour, returned by
/// [`HookBuilder::redirect`]. Call [`install`](Self::install) to create the
/// hook.
#[must_use = "a hook builder does nothing until `install` is called"]
pub struct HookWith<F: Function> {
    target: *const (),
    detour: F,
}

impl<F: Function> HookWith<F> {
    /// Installs the hook, disabled. Enable it with [`Hook::enable`].
    ///
    /// Fails with [`Error::AlreadyHooked`] if the target address is already
    /// hooked by another detour or injection.
    ///
    /// # Safety
    ///
    /// - `target` must point to a function with the signature `F` (and not one
    ///   that the compiler may have inlined into all of its callers).
    /// - The detour must be compatible with that signature and calling
    ///   convention.
    ///
    /// As with any inline hook, only calls that actually reach the target are
    /// redirected; inlined calls are not.
    pub unsafe fn install(self) -> Result<Hook<F>> {
        let address = self.target as usize;

        // Reserve the address first, so a second hook on it is refused.
        if !registry::claim(address) {
            return Err(Error::AlreadyHooked { address });
        }

        // SAFETY: The caller guarantees `target` points to a function of
        // signature `F`.
        let target_fn: F = unsafe { F::from_ptr(self.target) };

        // SAFETY: The target and detour share the signature `F`, as required.
        match unsafe { detour::TypedDetour::<F>::new(target_fn, self.detour) } {
            Ok(inner) => Ok(Hook {
                inner,
                target: address,
            }),
            Err(error) => {
                registry::release(address);
                Err(Error::from_detour(error, address))
            }
        }
    }
}
