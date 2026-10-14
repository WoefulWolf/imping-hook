//! A process-wide registry of hooked addresses.
//!
//! A second hook on an address that is already hooked (by a detour or an
//! injection) is refused rather than chained. The registry belongs to one
//! loaded copy of this crate, so it does not see hooks installed by other
//! copies, such as those linked into other mod DLLs.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex, MutexGuard};

static HOOKED: LazyLock<Mutex<HashSet<usize>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Locks the registry, recovering from a poisoned lock rather than panicking:
/// the set is a plain collection with no broken invariant to uphold.
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
