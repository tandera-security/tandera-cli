//! Small shared helpers with no better home of their own.

use std::sync::{Mutex, MutexGuard};

/// Lock a mutex, recovering from poisoning instead of panicking — a panic on
/// one background job/thread must never take the whole process down.
/// Shared by `capture::uploads::Queue` (its receipts/outstanding-count
/// locks) and `repl::Session` (its `SharedState` lock).
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
