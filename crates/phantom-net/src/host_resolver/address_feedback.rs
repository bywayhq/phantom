//! DNS-record failure history, separate from connection-pool family memory.

use std::{
    collections::TryReserveError,
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex, MutexGuard, PoisonError, Weak},
};

/// One resolver-owned record. Refresh its answers without replacing its history.
///
/// The caller owns the DNS key, answer TTL and allocation of the shared `Arc`.
/// Replacing that Arc for clear/eviction isolates every old cursor and witness.
pub(crate) struct AddressRecord {
    capacity: NonZeroUsize,
    state: Mutex<RecordState>,
}

struct RecordState {
    generation: u64,
    addresses: Vec<SocketAddr>,
    unusable: Vec<IpAddr>,
}

/// A traversal of one record; an exhausted traversal stays exhausted.
#[derive(Clone, Debug)]
pub(crate) struct AddressCursor {
    record: Arc<AddressRecord>,
    generation: u64,
    next_index: usize,
    done: bool,
}

/// The selected address and proof of the record generation that selected it.
pub(crate) struct SelectedAddress {
    address: SocketAddr,
    record: Weak<AddressRecord>,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReportOutcome {
    Added,
    AlreadyKnown,
    Stale,
}

/// Failure to retain feedback, without changing selection or existing history.
#[derive(Debug)]
pub(crate) enum FeedbackResourceError {
    HistoryCapacity { limit: NonZeroUsize },
    Allocation(TryReserveError),
    GenerationExhausted,
}

impl AddressRecord {
    /// Takes already-owned addresses and an explicit history bound. No default
    /// bound or browser-specific constant is supplied by this primitive.
    pub(crate) fn new(addresses: Vec<SocketAddr>, capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            state: Mutex::new(RecordState {
                generation: 0,
                addresses,
                unusable: Vec::new(),
            }),
        }
    }

    /// Updates the answer without resetting failed addresses. Old reports are
    /// ignored, while nonexhausted cursors restart on the new answer.
    pub(crate) fn refresh(&self, addresses: Vec<SocketAddr>) -> Result<(), FeedbackResourceError> {
        let mut state = self.lock();
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(FeedbackResourceError::GenerationExhausted)?;
        state.addresses = addresses;
        state.generation = generation;
        Ok(())
    }

    pub(crate) fn cursor(self: &Arc<Self>) -> AddressCursor {
        AddressCursor {
            record: Arc::clone(self),
            generation: self.lock().generation,
            next_index: 0,
            done: false,
        }
    }

    /// Reports only the address selected from this record's current answer.
    /// A caller must propagate a resource error; it does not authorize retry.
    pub(crate) fn report_unusable(
        self: &Arc<Self>,
        selected: &SelectedAddress,
    ) -> Result<ReportOutcome, FeedbackResourceError> {
        let Some(owner) = selected.record.upgrade() else {
            return Ok(ReportOutcome::Stale);
        };
        if !Arc::ptr_eq(self, &owner) {
            return Ok(ReportOutcome::Stale);
        }
        let mut state = self.lock();
        if state.generation != selected.generation {
            return Ok(ReportOutcome::Stale);
        }
        // Firefox's DNS.cpp:95-112 (fdd757a2e09c) formats only IP bytes.
        // Port, IPv6 scope ID and flow label do not participate in the string
        // used by AddrHostRecord's unusable list. Keep the original socket
        // address, including those fields, for the actual dial.
        let identity = selected.address.ip();
        if state.unusable.contains(&identity) {
            return Ok(ReportOutcome::AlreadyKnown);
        }
        if state.unusable.len() == self.capacity.get() {
            return Err(FeedbackResourceError::HistoryCapacity {
                limit: self.capacity,
            });
        }
        state
            .unusable
            .try_reserve(1)
            .map_err(FeedbackResourceError::Allocation)?;
        state.unusable.push(identity);
        Ok(ReportOutcome::Added)
    }

    fn lock(&self) -> MutexGuard<'_, RecordState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl AddressCursor {
    /// Reads shared history on each selection, preserving answer order and
    /// duplicates. A fresh all-blocked traversal resets history and tries first
    /// (`nsDNSService2.cpp:163-218`, Firefox revision fdd757a2e09c).
    #[cfg(test)]
    pub(crate) fn next(&mut self) -> Option<SelectedAddress> {
        self.next_matching(|_| true)
    }

    pub(crate) fn next_matching(
        &mut self,
        accepts: impl Fn(&SocketAddr) -> bool,
    ) -> Option<SelectedAddress> {
        if self.done {
            return None;
        }
        let mut state = self.record.lock();
        if self.generation != state.generation {
            self.generation = state.generation;
            self.next_index = 0;
        }
        let fresh = self.next_index == 0;
        let selected = state
            .addresses
            .iter()
            .enumerate()
            .skip(self.next_index)
            .find(|(_, address)| accepts(address) && !state.unusable.contains(&address.ip()))
            .map(|(index, address)| (index, *address));
        let selected = match selected {
            Some(selected) => Some(selected),
            None if fresh
                && !state
                    .addresses
                    .iter()
                    .any(|address| !state.unusable.contains(&address.ip())) =>
            {
                let eligible = state
                    .addresses
                    .iter()
                    .enumerate()
                    .find(|(_, address)| accepts(address))
                    .map(|(index, address)| (index, *address));
                if eligible.is_some() {
                    state.unusable.clear();
                }
                eligible
            }
            None => None,
        };
        match selected {
            Some((index, address)) => {
                self.next_index = index + 1;
                Some(SelectedAddress {
                    address,
                    record: Arc::downgrade(&self.record),
                    generation: self.generation,
                })
            }
            None => {
                self.done = true;
                None
            }
        }
    }
}

impl SelectedAddress {
    pub(crate) fn report_unusable(&self) -> Result<ReportOutcome, FeedbackResourceError> {
        match self.record.upgrade() {
            Some(record) => record.report_unusable(self),
            None => Ok(ReportOutcome::Stale),
        }
    }

    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }
}

impl fmt::Debug for AddressRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        formatter
            .debug_struct("AddressRecord")
            .field("generation", &state.generation)
            .field("address_count", &state.addresses.len())
            .field("unusable_count", &state.unusable.len())
            .field("history_capacity", &self.capacity)
            .finish()
    }
}

impl fmt::Debug for SelectedAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedAddress")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for FeedbackResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HistoryCapacity { limit } => {
                write!(
                    formatter,
                    "DNS address failure history reached its configured capacity of {limit}"
                )
            }
            Self::Allocation(_) => {
                formatter.write_str("could not allocate DNS address failure history")
            }
            Self::GenerationExhausted => {
                formatter.write_str("DNS address record generation is exhausted")
            }
        }
    }
}

impl Error for FeedbackResourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            Self::HistoryCapacity { .. } | Self::GenerationExhausted => None,
        }
    }
}

#[cfg(test)]
mod tests;
