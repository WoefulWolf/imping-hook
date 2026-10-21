//! A process-wide registry of hooked addresses.
//!
//! A second hook on a hooked address is refused, not chained. Each loaded copy
//! of this crate has its own registry, so it doesn't see hooks from copies
//! linked into other mod DLLs.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex, MutexGuard};

static HOOKED: LazyLock<Mutex<HashSet<usize>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Locks the registry; poisoning is harmless, since a plain set has no
/// invariant to break.
fn registry() -> MutexGuard<'static, HashSet<usize>> {
    HOOKED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Claims `address`, returning `false` if it is already hooked.
pub(crate) fn claim(address: usize) -> bool {
    registry().insert(address)
}

/// Releases `address`, so it may be hooked again.
pub(crate) fn release(address: usize) {
    registry().remove(&address);
}
