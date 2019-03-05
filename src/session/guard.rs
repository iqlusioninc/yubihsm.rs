//! MutexGuard wrapper protecting an optional session which is always true

use super::Session;
use std::ops::{Deref, DerefMut};
use std::sync::MutexGuard;

/// Mutex-guarded wrapper type containing a locked session
pub struct Guard<'mutex>(MutexGuard<'mutex, Option<Session>>);

impl<'mutex> Guard<'mutex> {
    /// Create a session guard from a `MutexGuard`ed `Session`
    pub(crate) fn new(mutex_guard: MutexGuard<'mutex, Option<Session>>) -> Self {
        assert!(
            mutex_guard.is_some(),
            "session::Guard must wrap an active session"
        );
        Guard(mutex_guard)
    }
}

impl<'mutex> Deref for Guard<'mutex> {
    type Target = Session;

    fn deref(&self) -> &Session {
        self.0.deref().as_ref().unwrap()
    }
}

impl<'mutex> DerefMut for Guard<'mutex> {
    fn deref_mut(&mut self) -> &mut Session {
        self.0.deref_mut().as_mut().unwrap()
    }
}
