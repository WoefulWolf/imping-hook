//! Code injection at an arbitrary address: either the caller's own machine
//! code, or a register-context callback.
//!
//! Both flavours run the injected work, then the instructions they displaced,
//! then continue. They reuse [`detour::RawDetour`] for relocation and the
//! trampoline, and write only the stub themselves.

#[cfg(target_arch = "x86_64")]
use crate::context::Context;
use crate::error::{Error, OsError, Result};
use crate::registry;
use crate::sys;
use core::mem::ManuallyDrop;
use core::ptr;
use region::Protection;

/// The length of the absolute jump appended to a raw-bytes stub, per
/// architecture.
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

/// A boxed register-context callback (always invoked with `&mut Context`; the
/// read-only `inspect` wraps a `Fn(&Context)` into this shape).
#[cfg(target_arch = "x86_64")]
type ContextFn = dyn Fn(&mut Context) + Send + Sync;

/// A generous upper bound on the assembled size of a register-context stub.
/// The real stub is a few hundred bytes; the allocation is page-rounded anyway.
#[cfg(target_arch = "x86_64")]
const CONTEXT_STUB_CAPACITY: usize = 1024;

/// The Rust side of a register-context injection: invokes the callback with the
/// saved context. Reached from the stub with the Win64 argument registers set.
///
/// # Safety
///
/// `ctx` must point to a valid, writable [`Context`]; `closure` must be the
/// pointer installed for this injection, valid for the call.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn context_trampoline(ctx: *mut Context, closure: *mut Box<ContextFn>) {
    // SAFETY: both pointers are set up by the stub and valid for this call.
    let (closure, ctx): (&ContextFn, &mut Context) = unsafe { (&**closure, &mut *ctx) };
    // A panic must not unwind into the patched function (non-Rust frames), so
    // catch it and continue with the context as the closure left it.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| closure(ctx)));
}

/// Assembles the register-context stub: save the full context on the stack,
/// call [`context_trampoline`] with it and `closure_ptr`, restore the (possibly
/// modified) context, then jump to the trampoline — or, if the callback changed
/// `rip`, to the new address with the chosen `rsp`.
#[cfg(target_arch = "x86_64")]
fn assemble_context_stub(
    hook_addr: u64,
    closure_ptr: u64,
    rust_trampoline: u64,
    continue_at: u64,
) -> core::result::Result<Vec<u8>, iced_x86::IcedError> {
    use core::mem::{offset_of, size_of};
    use iced_x86::code_asm::*;

    let size = size_of::<Context>() as i64;
    let o_rflags = offset_of!(Context, rflags) as i64;
    let o_rsp = offset_of!(Context, rsp) as i64;
    let o_rbx = offset_of!(Context, rbx) as i64;
    let o_r11 = offset_of!(Context, r11) as i64;
    let o_rip = offset_of!(Context, rip) as i64;
    let o_xmm = offset_of!(Context, xmm) as i64;

    let xmms = [
        xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13,
        xmm14, xmm15,
    ];
    // Every general-purpose register except rsp, which is derived.
    let save = [
        (rax, offset_of!(Context, rax) as i64),
        (rbx, o_rbx),
        (rcx, offset_of!(Context, rcx) as i64),
        (rdx, offset_of!(Context, rdx) as i64),
        (rsi, offset_of!(Context, rsi) as i64),
        (rdi, offset_of!(Context, rdi) as i64),
        (rbp, offset_of!(Context, rbp) as i64),
        (r8, offset_of!(Context, r8) as i64),
        (r9, offset_of!(Context, r9) as i64),
        (r10, offset_of!(Context, r10) as i64),
        (r11, o_r11),
        (r12, offset_of!(Context, r12) as i64),
        (r13, offset_of!(Context, r13) as i64),
        (r14, offset_of!(Context, r14) as i64),
        (r15, offset_of!(Context, r15) as i64),
    ];
    // Restored directly; rbx, r11 and rsp are handled specially at the end.
    let restore = [
        (rax, offset_of!(Context, rax) as i64),
        (rcx, offset_of!(Context, rcx) as i64),
        (rdx, offset_of!(Context, rdx) as i64),
        (rsi, offset_of!(Context, rsi) as i64),
        (rdi, offset_of!(Context, rdi) as i64),
        (rbp, offset_of!(Context, rbp) as i64),
        (r8, offset_of!(Context, r8) as i64),
        (r9, offset_of!(Context, r9) as i64),
        (r10, offset_of!(Context, r10) as i64),
        (r12, offset_of!(Context, r12) as i64),
        (r13, offset_of!(Context, r13) as i64),
        (r14, offset_of!(Context, r14) as i64),
        (r15, offset_of!(Context, r15) as i64),
    ];

    let mut a = CodeAssembler::new(64)?;

    // --- Prologue: build the Context on the stack. ---
    a.sub(rsp, size as i32)?;
    for (reg, offset) in save {
        a.mov(qword_ptr(rsp + offset), reg)?;
    }
    a.lea(rax, qword_ptr(rsp + size))?; // original rsp (entry rsp, no return address was pushed)
    a.mov(qword_ptr(rsp + o_rsp), rax)?;
    a.pushfq()?;
    a.pop(rax)?;
    a.mov(qword_ptr(rsp + o_rflags), rax)?;
    a.mov(rax, hook_addr)?;
    a.mov(qword_ptr(rsp + o_rip), rax)?;
    for (index, xmm) in xmms.iter().copied().enumerate() {
        a.movups(xmmword_ptr(rsp + o_xmm + index as i64 * 16), xmm)?;
    }

    // --- Call context_trampoline(&ctx, closure). ---
    a.mov(rcx, rsp)?; // arg0 = &ctx
    a.mov(rbx, rsp)?; // keep &ctx across the call (rbx is callee-saved)
    a.mov(rdx, closure_ptr)?; // arg1 = closure
    a.and(rsp, -16)?; // align the stack
    a.sub(rsp, 32)?; // 32-byte shadow space
    a.mov(rax, rust_trampoline)?;
    a.call(rax)?;
    a.mov(rsp, rbx)?; // rsp = &ctx again

    // --- Epilogue: restore context, then jump to rip (or the trampoline). ---
    for (index, xmm) in xmms.iter().copied().enumerate() {
        a.movups(xmm, xmmword_ptr(rbx + o_xmm + index as i64 * 16))?;
    }
    a.mov(rax, qword_ptr(rbx + o_rflags))?;
    a.push(rax)?;
    a.popfq()?;

    // Target rip: continue through the displaced originals if rip is unchanged,
    // else the address the callback redirected to.
    a.mov(rax, qword_ptr(rbx + o_rip))?;
    a.mov(r11, hook_addr)?;
    a.cmp(rax, r11)?;
    a.mov(r11, continue_at)?;
    a.cmove(rax, r11)?;

    // Stage, on the target stack, the values the final pops/ret will load.
    a.mov(r11, qword_ptr(rbx + o_rsp))?; // r11 = target rsp
    a.mov(qword_ptr(r11 - 8), rax)?; // [target_rsp - 8]  = target rip (for ret)
    a.mov(rax, qword_ptr(rbx + o_rbx))?;
    a.mov(qword_ptr(r11 - 16), rax)?; // [target_rsp - 16] = ctx.rbx
    a.mov(rax, qword_ptr(rbx + o_r11))?;
    a.mov(qword_ptr(r11 - 24), rax)?; // [target_rsp - 24] = ctx.r11
    a.sub(r11, 24)?; // final rsp

    for (reg, offset) in restore {
        a.mov(reg, qword_ptr(rbx + offset))?;
    }

    a.mov(rsp, r11)?; // switch to the (possibly redirected) stack
    a.pop(r11)?; // ctx.r11
    a.pop(rbx)?; // ctx.rbx
    a.ret()?; // -> target rip, with rsp = ctx.rsp

    a.assemble(0)
}

/// An injection, and the RAII guard that owns it.
///
/// Reaching `target` runs the injected work — raw machine code
/// ([`code`](InjectionBuilder::code)) or a register-context callback
/// ([`inspect`](InjectionBuilder::inspect) / [`modify`](InjectionBuilder::modify))
/// — then the displaced original instructions, then continues. Build one with
/// [`Injection::at`].
///
/// # Thread safety and dropping
///
/// Enabling, disabling, and dropping an `Injection` suspend every other thread
/// whilst the code is patched, exactly like [`Hook`](crate::Hook). A
/// register-context callback may run on several threads at once, each with its
/// own [`Context`](crate::Context); use interior mutability for any state the
/// callback keeps of its own. On drop the patch is reverted and the stub (and
/// any callback) freed; if it cannot be reverted, they are leaked so the target
/// never jumps into freed memory. [`leak`](Self::leak) keeps an injection
/// installed for the rest of the process.
pub struct Injection {
    inner: detour::RawDetour,
    // Freed manually, and only once the target no longer jumps to it.
    stub: ManuallyDrop<region::Allocation>,
    // A `*mut Box<ContextFn>` for a register-context injection, else null.
    closure: *mut (),
    target: usize,
}

// `Injection` is `Send + Sync`: `detour::RawDetour` is both, the allocation is
// owned memory, the callback is `Send + Sync`, and the rest is a plain address.
// SAFETY: the stub is only mutated during construction (before it is shared)
// and freed during drop; all code modification is serialized by the backend's
// global patch lock.
unsafe impl Send for Injection {}
// SAFETY: see above; `&Injection` only exposes locked operations and atomics.
unsafe impl Sync for Injection {}

impl Injection {
    /// Begins building an injection at `target`.
    ///
    /// `target` is the address at which the injected work will run, as resolved
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

    /// Allocates the stub, creates the disabled detour, and writes the stub
    /// `render`ed from the trampoline address. Reserving the target address and
    /// releasing it on failure is the caller's responsibility.
    ///
    /// # Safety
    ///
    /// See [`InjectionWith::install`]. `closure` must be null, or a
    /// `*mut Box<ContextFn>` this injection should free on drop.
    unsafe fn install_stub(
        target: *const (),
        capacity: usize,
        closure: *mut (),
        render: impl FnOnce(usize) -> Vec<u8>,
    ) -> Result<Injection> {
        let address = target as usize;

        let mut stub = region::alloc(capacity, Protection::READ_WRITE).map_err(|error| {
            Error::Os(OsError::from_region(error, "allocating the injection stub"))
        })?;
        let stub_ptr = stub.as_mut_ptr::<u8>();
        let stub_size = stub.len();

        // Make it executable so the backend accepts it as the detour target.
        // SAFETY: `stub_ptr`/`stub_size` describe the allocation just created.
        unsafe { region::protect(stub_ptr, stub_size, Protection::READ_EXECUTE) }.map_err(
            |error| Error::Os(OsError::from_region(error, "protecting the injection stub")),
        )?;

        // Create the disabled detour: reaching `target` jumps to the stub. The
        // backend relocates the displaced instructions into a trampoline.
        // SAFETY: forwarded — `target` is executable code the caller vouches
        // for; the stub is executable and distinct from the target.
        let inner = unsafe { detour::RawDetour::new(target, stub_ptr.cast()) }
            .map_err(|error| Error::from_detour(error, address))?;
        let trampoline = inner.trampoline() as usize;

        let bytes = render(trampoline);
        assert!(
            bytes.len() <= stub_size,
            "imping-hook: injection stub exceeded its allocation"
        );

        // SAFETY: reverting to read-write the allocation we own.
        unsafe { region::protect(stub_ptr, stub_size, Protection::READ_WRITE) }.map_err(
            |error| Error::Os(OsError::from_region(error, "protecting the injection stub")),
        )?;
        // SAFETY: `stub_ptr` owns `stub_size >= bytes.len()` writable bytes, and
        // the source is disjoint from it.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), stub_ptr, bytes.len()) };
        // SAFETY: restoring execute protection on the allocation we own.
        unsafe { region::protect(stub_ptr, stub_size, Protection::READ_EXECUTE) }.map_err(
            |error| Error::Os(OsError::from_region(error, "protecting the injection stub")),
        )?;
        // SAFETY: the stub spans `stub_size` bytes of memory we own.
        unsafe { sys::flush_instruction_cache(stub_ptr, stub_size)? };

        Ok(Injection {
            inner,
            stub: ManuallyDrop::new(stub),
            closure,
            target: address,
        })
    }

    /// Builds a raw-bytes injection: the caller's code, then a jump to the
    /// trampoline.
    ///
    /// # Safety
    ///
    /// See [`InjectionWith::install`].
    unsafe fn build_bytes(target: *const (), code: Vec<u8>) -> Result<Injection> {
        let capacity = code.len() + ABS_JUMP_LEN;
        // SAFETY: forwarded from the caller.
        unsafe {
            Self::install_stub(target, capacity, ptr::null_mut(), move |trampoline| {
                let mut bytes = code;
                bytes.extend_from_slice(&absolute_jump(trampoline));
                bytes
            })
        }
    }

    /// Builds a register-context injection from a boxed callback.
    ///
    /// # Safety
    ///
    /// See [`InjectionWith::install`].
    #[cfg(target_arch = "x86_64")]
    unsafe fn build_context(target: *const (), closure: Box<ContextFn>) -> Result<Injection> {
        let hook_addr = target as usize as u64;
        let rust_trampoline = context_trampoline
            as unsafe extern "C" fn(*mut Context, *mut Box<ContextFn>)
            as usize as u64;
        // Leak the callback to a stable thin pointer the stub can reference.
        let closure_ptr: *mut Box<ContextFn> = Box::into_raw(Box::new(closure));

        // SAFETY: forwarded from the caller.
        let result = unsafe {
            Self::install_stub(
                target,
                CONTEXT_STUB_CAPACITY,
                closure_ptr.cast(),
                |continue_at| {
                    assemble_context_stub(
                        hook_addr,
                        closure_ptr as u64,
                        rust_trampoline,
                        continue_at as u64,
                    )
                    .expect("imping-hook: internal error assembling the context stub")
                },
            )
        };
        if result.is_err() {
            // SAFETY: `closure_ptr` came from `Box::into_raw` above and the stub
            // referencing it was never installed.
            drop(unsafe { Box::from_raw(closure_ptr) });
        }
        result
    }
}

impl Drop for Injection {
    fn drop(&mut self) {
        // Revert the patch through a transaction so no thread resumes mid-patch.
        // Only free the stub (and callback) if the target was restored;
        // otherwise it may still jump to the stub, so they are leaked and the
        // address stays reserved (the backend likewise leaks its own code).
        if self.toggle(false).is_ok() {
            registry::release(self.target);
            // SAFETY: the target no longer jumps to the stub, and neither the
            // stub nor the callback is used again.
            unsafe { ManuallyDrop::drop(&mut self.stub) };
            #[cfg(target_arch = "x86_64")]
            if !self.closure.is_null() {
                // SAFETY: `closure` is the `Box<ContextFn>` leaked for this
                // injection (null otherwise, excluded above).
                drop(unsafe { Box::from_raw(self.closure as *mut Box<ContextFn>) });
            }
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

/// The payload of an [`InjectionWith`]: raw bytes or a register-context
/// callback.
enum Payload {
    Bytes(Vec<u8>),
    #[cfg(target_arch = "x86_64")]
    Context(Box<ContextFn>),
}

/// An injection builder holding the target address, returned by
/// [`Injection::at`].
#[must_use = "an injection builder does nothing until the payload and `install` are set"]
pub struct InjectionBuilder {
    target: *const (),
}

impl InjectionBuilder {
    /// Injects the caller's own machine code at the target.
    ///
    /// The bytes are copied into the stub, so the slice need not outlive this
    /// call. The code must honour the platform ABI itself (see
    /// [`install`](InjectionWith::install)).
    pub fn code(self, code: &[u8]) -> InjectionWith {
        InjectionWith {
            target: self.target,
            payload: Payload::Bytes(code.to_vec()),
        }
    }

    /// Injects a read-only register-context callback.
    ///
    /// When the target is reached, `callback` is invoked with a shared
    /// [`Context`](crate::Context) of the saved registers; the original code
    /// then resumes unchanged. The callback may run on several threads at once,
    /// so it must be `Send + Sync` and use interior mutability for its own
    /// state.
    #[cfg(target_arch = "x86_64")]
    pub fn inspect<F>(self, callback: F) -> InjectionWith
    where
        F: Fn(&Context) + Send + Sync + 'static,
    {
        InjectionWith {
            target: self.target,
            payload: Payload::Context(Box::new(move |ctx: &mut Context| callback(ctx))),
        }
    }

    /// Injects a mutable register-context callback.
    ///
    /// Like [`inspect`](Self::inspect), but the callback receives a mutable
    /// [`Context`](crate::Context): writing a register changes it before the
    /// original code resumes. Changing `rip` redirects execution (skipping the
    /// displaced originals) to the new address with the chosen `rsp`.
    #[cfg(target_arch = "x86_64")]
    pub fn modify<F>(self, callback: F) -> InjectionWith
    where
        F: Fn(&mut Context) + Send + Sync + 'static,
    {
        InjectionWith {
            target: self.target,
            payload: Payload::Context(Box::new(callback)),
        }
    }
}

/// An injection builder holding the target and its payload, returned by
/// [`InjectionBuilder::code`], [`inspect`](InjectionBuilder::inspect) or
/// [`modify`](InjectionBuilder::modify). Call [`install`](Self::install) to
/// patch the target.
#[must_use = "an injection builder does nothing until `install` is called"]
pub struct InjectionWith {
    target: *const (),
    payload: Payload,
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
    ///   after the injected work runs.
    /// - For [`code`](InjectionBuilder::code): the bytes must be valid machine
    ///   code that honours the platform ABI — preserve every register and flag
    ///   the surrounding function relies on, keep the stack balanced and aligned
    ///   (reserving shadow space before any `call` on Windows x64), and not
    ///   branch into the displaced bytes. (The register-context callbacks handle
    ///   this for you.)
    pub unsafe fn install(self) -> Result<Injection> {
        let address = self.target as usize;

        // Reserve the address first, so a second hook on it is refused.
        if !registry::claim(address) {
            return Err(Error::AlreadyHooked { address });
        }

        let result = match self.payload {
            // SAFETY: forwarded from the caller.
            Payload::Bytes(code) => unsafe { Injection::build_bytes(self.target, code) },
            #[cfg(target_arch = "x86_64")]
            // SAFETY: forwarded from the caller.
            Payload::Context(callback) => unsafe {
                Injection::build_context(self.target, callback)
            },
        };
        if result.is_err() {
            registry::release(address);
        }
        result
    }
}
