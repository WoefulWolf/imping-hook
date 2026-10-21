//! Code injection at an arbitrary address: machine code, assembly, or a
//! register-context callback.
//!
//! Each runs the injected work, then the displaced instructions, then carries
//! on. [`detour::RawDetour`] does the relocation and trampoline; only the stub
//! is written here.

#[cfg(target_arch = "x86_64")]
use crate::context::Context;
use crate::error::{Error, OsError, Result};
use crate::registry;
use crate::sys;
use core::mem::ManuallyDrop;
use core::ptr;
use region::Protection;

/// The length of the absolute jump that ends a raw-bytes stub.
#[cfg(target_arch = "x86_64")]
const ABS_JUMP_LEN: usize = 14;
#[cfg(target_arch = "x86")]
const ABS_JUMP_LEN: usize = 6;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("imping-hook code injection supports only x86 and x86-64");

/// Builds an absolute jump to `target` that clobbers no registers or flags.
///
/// `jmp qword ptr [rip+0]` plus the address on x86-64; `push imm32; ret` on
/// x86, which leaves the stack and flags as they were.
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

/// A register-context callback; `inspect` wraps its `Fn(&Context)` into this
/// shape.
#[cfg(target_arch = "x86_64")]
type ContextFn = dyn Fn(&mut Context) + Send + Sync;

/// An [`InjectionBuilder::asm`] closure, run once at install.
#[cfg(target_arch = "x86_64")]
type BoxedAsm = Box<
    dyn FnOnce(
        &mut iced_x86::code_asm::CodeAssembler,
    ) -> core::result::Result<(), iced_x86::IcedError>,
>;

/// A generous upper bound on the size of a register-context stub.
///
/// The real stub is a few hundred bytes, and the allocation is page-rounded
/// anyway.
#[cfg(target_arch = "x86_64")]
const CONTEXT_STUB_CAPACITY: usize = 1024;

/// Calls a register-context callback with the saved context.
///
/// The stub calls this with the Win64 argument registers set.
///
/// # Safety
///
/// `ctx` must point to a valid, writable [`Context`], and `closure` to this
/// injection's callback, both valid for the call.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn context_trampoline(ctx: *mut Context, closure: *mut Box<ContextFn>) {
    // SAFETY: the stub passes both pointers, valid for this call.
    let (closure, ctx): (&ContextFn, &mut Context) = unsafe { (&**closure, &mut *ctx) };
    // Never unwind into the patched (non-Rust) frames; carry on with the
    // context as the closure left it.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| closure(ctx)));
}

/// Assembles the register-context stub.
///
/// It saves the full context on the stack, calls [`context_trampoline`],
/// restores the (maybe changed) context, then jumps to the trampoline, or to a
/// changed `rip` with the chosen `rsp`.
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

/// A code injection, and the RAII guard that owns it.
///
/// Reaching the target runs the injected work, then the displaced original
/// instructions, then the rest of the original code. The work is machine code
/// ([`code`](InjectionBuilder::code), [`asm`](InjectionBuilder::asm)) or a
/// register-context callback ([`inspect`](InjectionBuilder::inspect),
/// [`modify`](InjectionBuilder::modify)). Build one with [`Injection::at`].
///
/// # Threads, batches and dropping
///
/// These work as for [`Hook`](crate::Hook): patching suspends other threads,
/// [`batch`](crate::batch) queues changes, and dropping reverts the patch and
/// frees the stub and callback, or leaks them if the patch can't be reverted.
/// A callback may run on several threads at once, each with its own
/// [`Context`](crate::Context), so keep its own state in atomics or locks.
pub struct Injection {
    // Boxed so its address stays put while a `batch` has a change queued.
    inner: Box<detour::RawDetour>,
    // Freed manually, and only once the target no longer jumps to it.
    stub: ManuallyDrop<region::Allocation>,
    // A `*mut Box<ContextFn>` for a register-context injection, else null.
    closure: *mut (),
    target: usize,
}

// SAFETY: RawDetour and the callback are Send + Sync, the stub is only written
// before it's shared, and all patching goes through the global patch lock.
unsafe impl Send for Injection {}
// SAFETY: `&Injection` only exposes locked operations and atomics.
unsafe impl Sync for Injection {}

impl Injection {
    /// Starts building an injection at `target`.
    ///
    /// Nothing is patched until [`install`](InjectionWith::install).
    pub fn at(target: *const ()) -> InjectionBuilder {
        InjectionBuilder { target }
    }

    /// Enables the injection.
    ///
    /// Does nothing if already enabled. Suspends other threads while patching;
    /// see [`Injection`] for threads and batches.
    ///
    /// # Errors
    ///
    /// Returns an error naming the target if patching fails, such as
    /// [`Error::TargetModified`] when a third party changed its code.
    pub fn enable(&self) -> Result<()> {
        self.toggle(true)
    }

    /// Disables the injection, restoring the original code.
    ///
    /// Does nothing if already disabled. Suspends other threads while patching;
    /// see [`Injection`] for threads and batches.
    ///
    /// # Errors
    ///
    /// As for [`enable`](Self::enable).
    pub fn disable(&self) -> Result<()> {
        self.toggle(false)
    }

    /// Enables the injection without suspending other threads.
    ///
    /// Faster than [`enable`](Self::enable), and applied at once even inside a
    /// batch; see [`Hook`](crate::Hook#batches).
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

    /// Disables the injection without suspending other threads.
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

    /// Returns whether the injection is enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Keeps the injection installed for the rest of the process.
    ///
    /// It stays in its current state, so enable it first if it should stay
    /// active. The target address stays reserved.
    pub fn leak(self) {
        core::mem::forget(self);
    }

    /// Applies the change with every other thread suspended, or queues it
    /// inside a batch.
    fn toggle(&self, enable: bool) -> Result<()> {
        if crate::batch::queue(&*self.inner, self.target, enable) {
            return Ok(());
        }
        // SAFETY: `Threads::All` suspends every other thread and moves any that
        // stopped inside the patch; the caller isn't running the patched bytes.
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

    /// Allocates the stub, creates the disabled detour, and writes the bytes
    /// `render` builds from the stub and trampoline addresses.
    ///
    /// The caller claims the target address and releases it on failure.
    ///
    /// # Safety
    ///
    /// As for [`InjectionWith::install`]. `closure` must be null, or a
    /// `*mut Box<ContextFn>` the injection frees on drop.
    unsafe fn install_stub(
        target: *const (),
        capacity: usize,
        closure: *mut (),
        render: impl FnOnce(usize, usize) -> Vec<u8>,
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

        // SAFETY: the caller vouches for `target`; the stub is executable and
        // distinct from it.
        let inner = unsafe { detour::RawDetour::new(target, stub_ptr.cast()) }
            .map_err(|error| Error::from_detour(error, address))?;
        let trampoline = inner.trampoline() as usize;

        let bytes = render(stub_ptr as usize, trampoline);
        assert!(
            bytes.len() <= stub_size,
            "imping-hook: injection stub exceeded its allocation"
        );

        // SAFETY: we own this allocation.
        unsafe { region::protect(stub_ptr, stub_size, Protection::READ_WRITE) }.map_err(
            |error| Error::Os(OsError::from_region(error, "protecting the injection stub")),
        )?;
        // SAFETY: the stub has `stub_size >= bytes.len()` writable bytes and
        // doesn't overlap `bytes`.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), stub_ptr, bytes.len()) };
        // SAFETY: we own this allocation.
        unsafe { region::protect(stub_ptr, stub_size, Protection::READ_EXECUTE) }.map_err(
            |error| Error::Os(OsError::from_region(error, "protecting the injection stub")),
        )?;
        // SAFETY: the stub spans `stub_size` bytes of memory we own.
        unsafe { sys::flush_instruction_cache(stub_ptr, stub_size)? };

        Ok(Injection {
            inner: Box::new(inner),
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
    /// As for [`InjectionWith::install`].
    unsafe fn build_bytes(target: *const (), code: Vec<u8>) -> Result<Injection> {
        let capacity = code.len() + ABS_JUMP_LEN;
        // SAFETY: forwarded from the caller.
        unsafe {
            Self::install_stub(
                target,
                capacity,
                ptr::null_mut(),
                move |_stub, trampoline| {
                    let mut bytes = code;
                    bytes.extend_from_slice(&absolute_jump(trampoline));
                    bytes
                },
            )
        }
    }

    /// Builds a register-context injection from a boxed callback.
    ///
    /// # Safety
    ///
    /// As for [`InjectionWith::install`].
    #[cfg(target_arch = "x86_64")]
    unsafe fn build_context(target: *const (), closure: Box<ContextFn>) -> Result<Injection> {
        let hook_addr = target as usize as u64;
        let rust_trampoline = context_trampoline
            as unsafe extern "C" fn(*mut Context, *mut Box<ContextFn>)
            as usize as u64;
        // A thin, stable pointer for the stub to embed; freed on drop.
        let closure_ptr: *mut Box<ContextFn> = Box::into_raw(Box::new(closure));

        // SAFETY: forwarded from the caller.
        let result = unsafe {
            Self::install_stub(
                target,
                CONTEXT_STUB_CAPACITY,
                closure_ptr.cast(),
                |_stub, continue_at| {
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
            // SAFETY: `closure_ptr` came from `Box::into_raw` above, and no stub
            // using it was installed.
            drop(unsafe { Box::from_raw(closure_ptr) });
        }
        result
    }

    /// Builds an injection from assembly written with iced's `code_asm`.
    ///
    /// The block is assembled at the real stub address, so rip-relative
    /// operands resolve, and followed by a jump to the trampoline.
    ///
    /// # Safety
    ///
    /// As for [`InjectionWith::install`].
    #[cfg(target_arch = "x86_64")]
    unsafe fn build_asm(target: *const (), build: BoxedAsm) -> Result<Injection> {
        use iced_x86::code_asm::CodeAssembler;

        let address = target as usize;
        let mut assembler = CodeAssembler::new(64).map_err(|error| Error::Assembly {
            address,
            reason: error.to_string(),
        })?;
        if let Err(error) = build(&mut assembler) {
            // The failing instruction isn't added, so the count is its index.
            let index = assembler.instructions().len();
            return Err(Error::Assembly {
                address,
                reason: format!("instruction {index}: {error}"),
            });
        }
        // Encode at a dummy address just to size the stub; the address changes
        // relative operands, not the length.
        let capacity = assembler
            .assemble(0)
            .map_err(|error| Error::Assembly {
                address,
                reason: error.to_string(),
            })?
            .len()
            + ABS_JUMP_LEN;

        // SAFETY: forwarded from the caller.
        unsafe {
            Self::install_stub(
                target,
                capacity,
                ptr::null_mut(),
                move |stub, trampoline| {
                    // Can't fail once the sizing encode above succeeded.
                    let mut bytes = assembler
                        .assemble(stub as u64)
                        .expect("imping-hook: internal error reassembling injected asm");
                    bytes.extend_from_slice(&absolute_jump(trampoline));
                    bytes
                },
            )
        }
    }
}

impl Drop for Injection {
    fn drop(&mut self) {
        // Free the stub and callback only once the target is restored. If it
        // can't be, the target may still jump there, so they leak (as does
        // detour's own code) and the address stays reserved.
        crate::batch::forget(self.target);
        // SAFETY: as in `toggle`; the caller isn't running the patched bytes.
        if unsafe { self.toggle_now(false, detour::Threads::All) }.is_ok() {
            registry::release(self.target);
            // SAFETY: the target no longer jumps to the stub, and neither the
            // stub nor the callback is used again.
            unsafe { ManuallyDrop::drop(&mut self.stub) };
            #[cfg(target_arch = "x86_64")]
            if !self.closure.is_null() {
                // SAFETY: a non-null `closure` is this injection's boxed
                // callback from `Box::into_raw`.
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

/// What an [`InjectionWith`] injects: raw bytes, an assembly builder, or a
/// register-context callback.
enum Payload {
    Bytes(Vec<u8>),
    #[cfg(target_arch = "x86_64")]
    Asm(BoxedAsm),
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
    /// The bytes are copied, so the slice needn't outlive this call. The code
    /// must follow the ABI rules of [`install`](InjectionWith::install).
    pub fn code(self, code: &[u8]) -> InjectionWith {
        InjectionWith {
            target: self.target,
            payload: Payload::Bytes(code.to_vec()),
        }
    }

    /// Injects machine code written as assembly.
    ///
    /// `build` appends to an [`asm::CodeAssembler`](crate::asm::CodeAssembler);
    /// pass Rust values as operands, e.g. `a.mov(rax, some_addr)`. It's
    /// assembled at the stub's real address, so rip-relative operands resolve,
    /// and the jump back is appended. The ABI rules of
    /// [`install`](InjectionWith::install) apply.
    #[cfg(target_arch = "x86_64")]
    pub fn asm<F>(self, build: F) -> InjectionWith
    where
        F: FnOnce(
                &mut crate::asm::CodeAssembler,
            ) -> core::result::Result<(), crate::asm::IcedError>
            + 'static,
    {
        InjectionWith {
            target: self.target,
            payload: Payload::Asm(Box::new(build)),
        }
    }

    /// Injects a callback that reads the registers at the target.
    ///
    /// `callback` gets the saved [`Context`](crate::Context), then the original
    /// code resumes unchanged. It may run on several threads at once; see
    /// [`Injection`].
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

    /// Injects a callback that can change the registers at the target.
    ///
    /// Like [`inspect`](Self::inspect), but register writes take effect before
    /// the original code resumes. Changing [`rip`](crate::Context::rip) jumps
    /// there instead, skipping the displaced instructions.
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

/// An injection builder holding the target and what to inject, returned by the
/// [`InjectionBuilder`] methods.
#[must_use = "an injection builder does nothing until `install` is called"]
pub struct InjectionWith {
    target: *const (),
    payload: Payload,
}

impl InjectionWith {
    /// Installs the injection, disabled; enable it with [`Injection::enable`].
    ///
    /// # Errors
    ///
    /// [`Error::AlreadyHooked`] if a detour or injection already holds the
    /// address, [`Error::Assembly`] if [`asm`](InjectionBuilder::asm) code
    /// can't be encoded, otherwise an error naming the target if it can't be
    /// patched.
    ///
    /// # Safety
    ///
    /// - `target` must point to executable code whose first bytes can be
    ///   relocated, and which can be resumed after the injected work.
    /// - Code from [`code`](InjectionBuilder::code) or
    ///   [`asm`](InjectionBuilder::asm) must follow the platform ABI: preserve
    ///   every register and flag the surrounding code relies on, keep the stack
    ///   balanced and aligned (with shadow space before any `call` on Windows
    ///   x64), and not branch into the displaced bytes. Register-context
    ///   callbacks handle this themselves.
    pub unsafe fn install(self) -> Result<Injection> {
        let address = self.target as usize;

        // Claim the address up front so a second hook on it is refused.
        if !registry::claim(address) {
            return Err(Error::AlreadyHooked { address });
        }

        let result = match self.payload {
            // SAFETY: forwarded from the caller.
            Payload::Bytes(code) => unsafe { Injection::build_bytes(self.target, code) },
            #[cfg(target_arch = "x86_64")]
            // SAFETY: forwarded from the caller.
            Payload::Asm(build) => unsafe { Injection::build_asm(self.target, build) },
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
