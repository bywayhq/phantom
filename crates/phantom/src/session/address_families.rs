//! The address family each origin's backup connections use, shared by the
//! pool entries of that origin on every runtime.

use std::sync::{Arc, Weak};

use phantom_net::tcp::AddressFamilyMemory;

/// The address family memory of each origin and route of one pool.
///
/// Pool entries are keyed by runtime as well, but the family an origin
/// answers on is learned state about the origin, as Firefox keeps it on the
/// origin's `ConnectionEntry`, so every runtime's entry for one origin and
/// route shares one memory, as per-origin admission does. A memory lives
/// while any entry holds it.
pub(super) struct AddressFamilies<Key> {
    entries: Vec<(Key, Weak<AddressFamilyMemory>)>,
}

impl<Key> Default for AddressFamilies<Key> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<Key> AddressFamilies<Key>
where
    Key: Clone + Eq,
{
    /// The memory of `origin`, a pool key without its runtime.
    pub(super) fn get(&mut self, origin: &Key) -> Arc<AddressFamilyMemory> {
        self.entries
            .retain(|(_, memory)| memory.strong_count() != 0);
        if let Some(memory) = self.entries.iter().find_map(|(candidate, memory)| {
            (candidate == origin).then(|| memory.upgrade()).flatten()
        }) {
            return memory;
        }
        let memory = Arc::new(AddressFamilyMemory::new());
        self.entries.push((origin.clone(), Arc::downgrade(&memory)));
        memory
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use phantom_net::tcp::AddressFamily;

    use super::AddressFamilies;

    #[test]
    fn one_origin_shares_one_memory_and_another_has_its_own() {
        let mut families = AddressFamilies::default();
        let first = families.get(&"a.test");
        let again = families.get(&"a.test");
        let other = families.get(&"b.test");

        assert!(Arc::ptr_eq(&first, &again));
        assert!(!Arc::ptr_eq(&first, &other));
        first.remember(AddressFamily::Ipv4);
        assert_eq!(again.family(), Some(AddressFamily::Ipv4));
        assert_eq!(other.family(), None);
    }

    #[test]
    fn a_memory_no_entry_holds_is_dropped() {
        let mut families = AddressFamilies::default();
        families.get(&"a.test").remember(AddressFamily::Ipv6);

        assert_eq!(families.get(&"a.test").family(), None);
    }
}
