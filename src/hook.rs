//! Typed function detours.

use crate::error::{Error, Result};
use crate::function::Function;
use crate::registry;
use crate::scan::{Pattern, Target};

/// A typed function detour, and the RAII guard that owns it.
///
/// While enabled, calls to the target run a detour of the same signature `F`
/// instead; the original stays callable through [`original`](Self::original).
/// Build one with [`Hook::at`], or [`Hook::scan`] to find the target by a byte
/// pattern.
///
/// # Threads
///
/// [`enable`](Self::enable), [`disable`](Self::disable) and drop suspend every
/// other thread while patching and move any thread stopped inside the patched
/// bytes, so hooks can be toggled in a running, multi-threaded process. Don't
/// toggle or drop a hook from inside its own target on the same thread. The
/// `unsafe` `*_unsuspended` methods skip the suspension.
///
/// # Batches
///
/// Inside [`batch`](crate::batch), `enable` and `disable` are queued and
/// applied together when the batch ends. The `*_unsuspended` methods apply at
/// once even there, and replace any change queued for the same hook.
///
/// # Dropping
///
/// Dropping a hook disables it and frees its generated code. If it can't be
/// disabled, say because a third party rewrote the target, the code is leaked
/// instead so the target never jumps into freed memory. [`leak`](Self::leak)
/// keeps a hook installed on purpose.
///
/// # Examples
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
    // Boxed so its address stays put while a `batch` has a change queued.
    inner: Box<detour::TypedDetour<F>>,
    target: usize,
}

// Non-generic so `Hook::at(..)` needs no turbofish; `redirect` fixes `F`.
impl Hook {
    /// Starts building a hook of the function at `target`.
    ///
    /// Nothing is patched until [`install`](HookWith::install).
    pub fn at(target: *const ()) -> HookBuilder {
        HookBuilder { target }
    }

    /// Starts building a hook of the function a byte pattern finds.
    ///
    /// The pattern is searched for in the main module's code when the hook is
    /// installed, and must match exactly once; see [`scan`](crate::scan) for
    /// the syntax.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use imping_hook::Hook;
    /// # extern "C" fn my_detour(a: i32) -> i32 { a }
    /// # fn main() -> imping_hook::Result<()> {
    /// // SAFETY: the pattern finds a function with the detour's signature.
    /// let hook = unsafe {
    ///     Hook::scan("48 89 5C 24 ?? 57 48 83 EC 20")
    ///         .in_module("engine.dll")
    ///         .redirect(my_detour as extern "C" fn(i32) -> i32)
    ///         .install()?
    /// };
    /// # Ok(())
    /// # }
    /// ```
    pub fn scan(pattern: &str) -> HookScan {
        HookScan {
            pattern: Pattern::new(pattern),
        }
    }
}

// Send + Sync come for free: TypedDetour is both and the rest is an address.
impl<F: Function> Hook<F> {
    /// Enables the hook, redirecting the target to the detour.
    ///
    /// Does nothing if already enabled. Suspends other threads while patching;
    /// see [`Hook`] for threads and batches.
    ///
    /// # Errors
    ///
    /// Returns an error naming the target if patching fails, such as
    /// [`Error::TargetModified`] when a third party changed its code.
    pub fn enable(&self) -> Result<()> {
        self.toggle(true)
    }

    /// Disables the hook, restoring the original function.
    ///
    /// Does nothing if already disabled. Suspends other threads while patching;
    /// see [`Hook`] for threads and batches.
    ///
    /// # Errors
    ///
    /// As for [`enable`](Self::enable).
    pub fn disable(&self) -> Result<()> {
        self.toggle(false)
    }

    /// Enables the hook without suspending other threads.
    ///
    /// Faster than [`enable`](Self::enable), and applied at once even inside a
    /// batch; see [`Hook`].
    ///
    /// # Errors
    ///
    /// As for [`enable`](Self::enable).
    ///
    /// # Safety
    ///
    /// No other thread may run the target's first bytes while they are
    /// written, or it may execute a half-written instruction.
    pub unsafe fn enable_unsuspended(&self) -> Result<()> {
        crate::batch::forget(self.target);
        // SAFETY: forwarded from the caller.
        unsafe { self.toggle_now(true, detour::Threads::None) }
    }

    /// Disables the hook without suspending other threads.
    ///
    /// Applied at once like [`enable_unsuspended`](Self::enable_unsuspended).
    ///
    /// # Errors
    ///
    /// As for [`enable`](Self::enable).
    ///
    /// # Safety
    ///
    /// No other thread may run the target's first bytes while the original
    /// ones are written back.
    pub unsafe fn disable_unsuspended(&self) -> Result<()> {
        crate::batch::forget(self.target);
        // SAFETY: forwarded from the caller.
        unsafe { self.toggle_now(false, detour::Threads::None) }
    }

    /// Returns whether the hook is enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Returns the original, unhooked function, borrowed from the hook.
    ///
    /// Callable whether or not the hook is enabled; see [`Original`](crate::Original).
    pub fn original(&self) -> F::Original<'_> {
        self.inner.original()
    }

    /// Returns the original function as a pointer not tied to the hook's
    /// lifetime.
    ///
    /// Prefer [`original`](Self::original) unless the pointer has to outlive a
    /// borrow.
    ///
    /// # Safety
    ///
    /// Don't call the returned function after the hook is dropped. Use
    /// [`leak`](Self::leak) if it must stay callable.
    pub unsafe fn trampoline(&self) -> F {
        // SAFETY: forwarded from the caller.
        unsafe { self.inner.trampoline() }
    }

    /// Keeps the hook installed for the rest of the process and returns the
    /// original function.
    ///
    /// The hook stays in its current state, so enable it first if it should
    /// stay active. The target address stays reserved.
    pub fn leak(self) -> F {
        // SAFETY: `self` is forgotten right away, so the trampoline is never
        // freed and stays valid for `'static`.
        let original = unsafe { self.inner.trampoline() };
        core::mem::forget(self);
        original
    }

    /// Applies the change with every other thread suspended, or queues it
    /// inside a batch.
    fn toggle(&self, enable: bool) -> Result<()> {
        if crate::batch::queue(&*self.inner, self.target, enable) {
            return Ok(());
        }
        // SAFETY: `Threads::All` suspends every other thread and moves any that
        // stopped inside the patch; the caller isn't running the target's prolog.
        unsafe { self.toggle_now(enable, detour::Threads::All) }
    }

    /// Applies the change now, in its own transaction.
    ///
    /// # Safety
    ///
    /// Threads not suspended by `threads` must not run the patched bytes while
    /// they are written.
    unsafe fn toggle_now(&self, enable: bool, threads: detour::Threads<'_>) -> Result<()> {
        let mut transaction = detour::Transaction::new();
        if enable {
            transaction.enable(&*self.inner);
        } else {
            transaction.disable(&*self.inner);
        }
        // SAFETY: forwarded from the caller.
        unsafe { transaction.commit(threads) }
            .map_err(|error| Error::from_detour(error, self.target))
    }
}

impl<F: Function> Drop for Hook<F> {
    fn drop(&mut self) {
        // Release the address only once the target is restored. If it can't
        // be, it's still patched (detour leaks its code) and stays reserved.
        crate::batch::forget(self.target);
        // SAFETY: as in `toggle`; the caller isn't running the target's prolog.
        if unsafe { self.toggle_now(false, detour::Threads::All) }.is_ok() {
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
    /// Sets the detour to redirect the target to, which fixes the hook's
    /// signature `F`.
    pub fn redirect<F: Function>(self, detour: F) -> HookWith<F> {
        HookWith {
            target: Target::Address(self.target),
            detour,
        }
    }
}

/// A hook builder holding a byte pattern to find the target by, returned by
/// [`Hook::scan`].
#[must_use = "a hook builder does nothing until `redirect` and `install` are called"]
pub struct HookScan {
    pattern: Pattern,
}

impl HookScan {
    /// Searches a loaded module such as `"engine.dll"` instead of the main
    /// module.
    pub fn in_module(self, module: &str) -> Self {
        HookScan {
            pattern: self.pattern.in_module(module),
        }
    }

    /// Moves the target this many bytes on from the start of the match, or back
    /// for a negative count.
    pub fn offset(self, bytes: isize) -> Self {
        HookScan {
            pattern: self.pattern.offset(bytes),
        }
    }

    /// Follows the `call` or `jmp` at the target to the function it goes to;
    /// see [`Pattern::follow_call`].
    pub fn follow_call(self) -> Self {
        HookScan {
            pattern: self.pattern.follow_call(),
        }
    }

    /// Sets the detour to redirect the target to, which fixes the hook's
    /// signature `F`.
    pub fn redirect<F: Function>(self, detour: F) -> HookWith<F> {
        HookWith {
            target: Target::Pattern(self.pattern),
            detour,
        }
    }
}

/// A hook builder holding the target and detour, returned by
/// [`HookBuilder::redirect`] and [`HookScan::redirect`].
#[must_use = "a hook builder does nothing until `install` is called"]
pub struct HookWith<F: Function> {
    target: Target,
    detour: F,
}

impl<F: Function> HookWith<F> {
    /// Installs the hook, disabled; enable it with [`Hook::enable`].
    ///
    /// Only calls that reach the target are redirected; copies inlined into
    /// callers are not.
    ///
    /// # Errors
    ///
    /// - The [`scan`](crate::scan) errors, for a hook built with
    ///   [`Hook::scan`].
    /// - [`Error::AlreadyHooked`] if a detour or injection already holds the
    ///   address.
    /// - Otherwise an error naming the target if it can't be patched.
    ///
    /// # Safety
    ///
    /// - The target (the address given to [`Hook::at`], or what
    ///   [`Hook::scan`] finds) must be a function with signature `F`, not one
    ///   the compiler may have inlined into all its callers.
    /// - The detour must match that signature and calling convention.
    pub unsafe fn install(self) -> Result<Hook<F>> {
        let target = self.target.resolve()?;
        let address = target as usize;

        // Claim the address up front so a second hook on it is refused.
        if !registry::claim(address) {
            return Err(Error::AlreadyHooked { address });
        }

        // SAFETY: the caller guarantees `target` is a function of signature `F`.
        let target_fn: F = unsafe { F::from_ptr(target) };

        // SAFETY: the target and detour share the signature `F`.
        match unsafe { detour::TypedDetour::<F>::new(target_fn, self.detour) } {
            Ok(inner) => Ok(Hook {
                inner: Box::new(inner),
                target: address,
            }),
            Err(error) => {
                registry::release(address);
                Err(Error::from_detour(error, address))
            }
        }
    }
}
