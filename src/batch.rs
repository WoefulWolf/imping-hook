//! Committing many enables and disables in one transaction.
//!
//! Every transaction suspends all other threads, and finding them can take tens
//! of milliseconds on a busy system, so patches applied one at a time add up.
//! Inside [`batch`], enables and disables on the calling thread are queued and
//! committed together once the closure returns.

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

// SAFETY: the pointer is only dereferenced while `QUEUE` is locked, and an
// owner removes its entries (taking the same lock) before freeing the detour,
// which is `Sync`.
unsafe impl Send for Pending {}

/// Changes queued by every thread currently in a [`batch`]. Kept in one place
/// so that a patch dropped on any thread removes its entries, and locked while
/// changes are committed so that it can't be freed meanwhile.
static QUEUE: Mutex<Vec<Pending>> = Mutex::new(Vec::new());

thread_local! {
    /// Whether this thread is inside a [`batch`].
    static BATCHING: Cell<bool> = const { Cell::new(false) };
}

fn lock() -> MutexGuard<'static, Vec<Pending>> {
    // A panic while locked leaves the queue consistent: entries are only
    // pushed or removed whole.
    QUEUE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs `f`, committing every enable and disable it makes on this thread in
/// one transaction when it returns, so other threads are suspended once
/// instead of once per patch.
///
/// Inside the closure, `enable` and `disable` of [`Injection`](crate::Injection)
/// and [`Hook`](crate::Hook) are queued and return `Ok` at once, and
/// `is_enabled` reports the state before the batch. The last change queued for
/// a patch wins. A `batch` inside another joins it. Only the calling thread's
/// changes are queued; other threads apply theirs as usual. If the closure
/// panics, the queued changes are still committed before the panic continues.
///
/// Returns the errors of changes that could not be applied, each naming its
/// address. If committing everything together fails, each change is tried on
/// its own, so one bad patch doesn't hold back the rest.
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

/// Commits this thread's queue when the outermost `batch` ends, also when
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

/// Queues a change if this thread is in a batch. Returns `false` when it isn't,
/// and the caller applies the change itself.
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

/// Drops every change queued for `target` by any thread, before its detour is
/// freed or when a change is applied directly. Waits for a commit in progress.
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
    // The lock stays held until the changes are applied, so no owner can free
    // a detour in the meantime.
    let mut transaction = detour::Transaction::new();
    for p in &mine {
        // SAFETY: owners remove their entries (under this lock) before freeing
        // the detour, which they keep boxed, so every queued pointer is valid.
        let detour = unsafe { &*p.detour };
        if p.enable {
            transaction.enable(detour);
        } else {
            transaction.disable(detour);
        }
    }
    // SAFETY: as for a single change: `Threads::All` suspends every other
    // thread, and the caller must not be executing the patched bytes.
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
