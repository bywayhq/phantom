//! Keeps refreshed connection owners alive while their weak background setup runs.

use std::sync::{Arc, Mutex, PoisonError};

pub(super) struct RetiredConnections<T> {
    owners: Mutex<Vec<Arc<T>>>,
}

impl<T> Default for RetiredConnections<T> {
    fn default() -> Self {
        Self {
            owners: Mutex::new(Vec::new()),
        }
    }
}

impl<T> RetiredConnections<T> {
    // Call under the owner's connection lock, shared with pending-setup removal.
    pub(super) fn retain(&self, owner: &Arc<T>) {
        let mut owners = self.owners.lock().unwrap_or_else(PoisonError::into_inner);
        if !owners.iter().any(|candidate| Arc::ptr_eq(candidate, owner)) {
            owners.push(Arc::clone(owner));
        }
    }

    // The caller drops the returned owner after releasing its connection lock.
    pub(super) fn take(&self, owner: &Arc<T>) -> Option<Arc<T>> {
        let mut owners = self.owners.lock().unwrap_or_else(PoisonError::into_inner);
        let position = owners
            .iter()
            .position(|candidate| Arc::ptr_eq(candidate, owner))?;
        Some(owners.swap_remove(position))
    }
}
