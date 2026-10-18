//! Keeps refreshed connection owners alive while their weak background setup runs.

use std::sync::{Arc, Mutex, PoisonError};

pub(super) struct RetiredConnections {
    // Only identity and lifetime matter here; erase the recursive owner type.
    owners: Mutex<Vec<Arc<dyn Send + Sync>>>,
}

impl Default for RetiredConnections {
    fn default() -> Self {
        Self {
            owners: Mutex::new(Vec::new()),
        }
    }
}

impl RetiredConnections {
    // Call under the owner's connection lock, shared with pending-setup removal.
    pub(super) fn retain<T: Send + Sync + 'static>(&self, owner: &Arc<T>) {
        let mut owners = self.owners.lock().unwrap_or_else(PoisonError::into_inner);
        if !owners
            .iter()
            .any(|candidate| std::ptr::addr_eq(Arc::as_ptr(candidate), Arc::as_ptr(owner)))
        {
            owners.push(Arc::clone(owner) as Arc<dyn Send + Sync>);
        }
    }

    // The caller drops the returned owner after releasing its connection lock.
    pub(super) fn take<T>(&self, owner: &Arc<T>) -> Option<Arc<dyn Send + Sync>> {
        let mut owners = self.owners.lock().unwrap_or_else(PoisonError::into_inner);
        let position = owners
            .iter()
            .position(|candidate| std::ptr::addr_eq(Arc::as_ptr(candidate), Arc::as_ptr(owner)))?;
        Some(owners.swap_remove(position))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retaining_the_same_allocation_twice_keeps_one_owner() {
        let registry = RetiredConnections::default();
        let owner = Arc::new(7_u8);
        registry.retain(&owner);
        registry.retain(&owner);

        assert_eq!(Arc::strong_count(&owner), 2);
        let retained = registry.take(&owner);
        assert!(retained.is_some());
        assert!(registry.take(&owner).is_none());
        drop(retained);
        assert_eq!(Arc::strong_count(&owner), 1);
    }

    #[test]
    fn taking_one_allocation_preserves_an_equal_but_distinct_owner() {
        let registry = RetiredConnections::default();
        let first = Arc::new(7_u8);
        let second = Arc::new(7_u8);
        let first_weak = Arc::downgrade(&first);
        let second_weak = Arc::downgrade(&second);
        registry.retain(&first);
        registry.retain(&second);

        let retained = registry.take(&first);
        drop(first);
        assert!(first_weak.upgrade().is_some());
        drop(retained);
        assert!(first_weak.upgrade().is_none());

        drop(second);
        assert!(second_weak.upgrade().is_some());
        drop(registry);
        assert!(second_weak.upgrade().is_none());
    }
}
