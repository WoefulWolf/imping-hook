//! Committing many enables and disables in one transaction.
//!
//! Each transaction suspends every other thread, and finding them can take
//! tens of milliseconds on a busy system, so one transaction per patch adds up.

use crate::error::{Error, Result};
use std::cell::Cell;
use std::sync::{Mutex, MutexGuard};
use std::thread::{self, ThreadId};

/// A queued change of one patch.
struct Pending {
    /// The batching thread that queued it.
    thread: ThreadId,
    /// The patch's detour. Its owner keeps it boxed, so the address is stable,
    /// and removes its entries with [`forget`] before freeing it.
    detour: *const (dyn detour::Detour + 'static),
    target: usize,
    enable: bool,
}

// SAFETY: the pointer is only dereferenced under the `QUEUE` lock, and owners
// remove their entries under that lock before freeing the (Sync) detour.
unsafe impl Send for Pending {}

/// Changes queued by every thread in a [`batch`].
///
/// Shared so a patch dropped on any thread can remove its entries, and locked
/// during a commit so no detour is freed meanwhile.
static QUEUE: Mutex<Vec<Pending>> = Mutex::new(Vec::new());

thread_local! {
    /// Whether this thread is inside a [`batch`].
    static BATCHING: Cell<bool> = const { Cell::new(false) };
}

fn lock() -> MutexGuard<'static, Vec<Pending>> {
    // Poisoning is harmless: entries are only pushed or removed whole.
    QUEUE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs `f`, then applies the enables and disables it made on this thread in
/// one transaction, so other threads are suspended once rather than per patch.
///
/// Inside `f`, `enable` and `disable` on a [`Hook`](crate::Hook) or
/// [`Injection`](crate::Injection) are queued and return `Ok` at once, and
/// `is_enabled` still reports the old state. The last change queued for a
/// patch wins, a nested `batch` joins the outer one, and other threads aren't
/// affected. If `f` panics, the queue is still applied before the panic goes on.
///
/// Returns an error, naming the address, for each change that couldn't be
/// applied. If applying them together fails, each is retried alone, so one bad
/// patch doesn't hold back the rest.
///
/// # Examples
///
/// ```no_run
/// use imping_hook::Injection;
///
/// # fn targets() -> Vec<*const ()> { Vec::new() }
/// let mut injections = Vec::new();
/// for target in targets() {
///     // SAFETY: each target is an instruction start of a function this
///     // program owns, and a `nop` changes nothing.
///     injections.push(unsafe { Injection::at(target).code(&[0x90]).install() }.unwrap());
/// }
/// let failed = imping_hook::batch(|| {
///     for injection in &injections {
///         injection.enable().expect("queued");
///     }
/// });
/// assert!(failed.is_empty());
/// ```
pub fn batch(f: impl FnOnce()) -> Vec<Error> {
    if BATCHING.with(|b| b.replace(true)) {
        // Nested: the outermost batch commits.
        f();
        return Vec::new();
    }
    let guard = Commit;
    f();
    guard.finish()
}

/// Applies this thread's queue when the outermost `batch` ends, even when
/// unwinding.
struct Commit;

impl Commit {
    fn finish(self) -> Vec<Error> {
        core::mem::forget(self);
        commit_current_thread()
    }
}

impl Drop for Commit {
    fn drop(&mut self) {
        // Only reached when unwinding; the errors can't be returned.
        let _ = commit_current_thread();
    }
}

/// Queues a change if this thread is in a batch, or returns `false` so the
/// caller applies it itself.
pub(crate) fn queue(detour: &(dyn detour::Detour + 'static), target: usize, enable: bool) -> bool {
    if !BATCHING.with(Cell::get) {
        return false;
    }
    let thread = thread::current().id();
    let mut queue = lock();
    queue.retain(|p| p.target != target);
    queue.push(Pending {
        thread,
        detour,
        target,
        enable,
    });
    true
}

/// Drops every change any thread queued for `target`.
///
/// Called before its detour is freed or a change is applied directly. Waits for
/// a commit in progress.
pub(crate) fn forget(target: usize) {
    lock().retain(|p| p.target != target);
}

/// Ends this thread's batch and applies its changes in one transaction, or
/// one by one if that fails.
fn commit_current_thread() -> Vec<Error> {
    BATCHING.with(|b| b.set(false));
    let thread = thread::current().id();
    let mut queue = lock();
    let (mine, others): (Vec<_>, Vec<_>) = queue.drain(..).partition(|p| p.thread == thread);
    *queue = others;
    if mine.is_empty() {
        return Vec::new();
    }
    // Hold the lock until everything is applied so no owner frees a detour.
    let mut transaction = detour::Transaction::new();
    for p in &mine {
        // SAFETY: owners remove their entries under this lock before freeing
        // their boxed detour, so every queued pointer is live.
        let detour = unsafe { &*p.detour };
        if p.enable {
            transaction.enable(detour);
        } else {
            transaction.disable(detour);
        }
    }
    // SAFETY: `Threads::All` suspends every other thread, and the caller isn't
    // running the patched bytes.
    if unsafe { transaction.commit(detour::Threads::All) }.is_ok() {
        return Vec::new();
    }
    mine.iter().filter_map(|p| commit_one(p).err()).collect()
}

fn commit_one(p: &Pending) -> Result<()> {
    // SAFETY: see `commit_current_thread`; the queue is still locked.
    let detour = unsafe { &*p.detour };
    let mut transaction = detour::Transaction::new();
    if p.enable {
        transaction.enable(detour);
    } else {
        transaction.disable(detour);
    }
    // SAFETY: see `commit_current_thread`.
    unsafe { transaction.commit(detour::Threads::All) }
        .map_err(|error| Error::from_detour(error, p.target))
}
