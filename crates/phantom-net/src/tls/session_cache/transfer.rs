//! Bounded native-backed capture and complete TCP store replacement.

use btls::ssl::{FrozenSessionPolicies, PreparedSessionPolicyFreeze, SessionImportPermit};

use super::*;
use crate::session_tickets::tcp_transfer::{
    MAX_OWNERS, MAX_RECORDS, TcpSessionExportRecord, TcpSessionRecordMetadata,
    TcpSessionStoreExport, TcpSessionStoreHeader, reserved, validate_hostname,
};

struct Destination {
    inner: Arc<CacheInner>,
    binding: SessionPolicyBinding,
    hostname: Arc<str>,
    header: TcpSessionStoreHeader,
}

/// Sessions remain private from permit consumption through the complete swap.
pub(crate) struct PreparedTlsSessionReplacement {
    destination: Destination,
    payload: Replacement,
    committed: bool,
}

struct Replacement {
    sessions: VecDeque<CachedSession>,
    generation: Arc<()>,
    next_batch: u64,
}

/// Preallocated pending references, kept alive until every transaction guard drops.
pub(crate) struct PreparedTlsSessionCapture {
    owner: TlsSessionOwner,
    binding: SessionPolicyBinding,
    hostname: Arc<str>,
    original_index: usize,
    records: Vec<TcpSessionExportRecord>,
    header: Option<TcpSessionStoreHeader>,
    attempted: bool,
}

/// Capture validation borrows the exact store, plan and held native policies.
pub(crate) struct ValidatedTlsSessionCapture<'a, 'store, 'native> {
    frozen: &'a FrozenTlsSessionCache<'store>,
    prepared: &'a mut PreparedTlsSessionCapture,
    _policies: &'a FrozenSessionPolicies<'native>,
    header: TcpSessionStoreHeader,
    now: u64,
}

/// Hold every transaction's validation token before committing any replacement.
pub(crate) struct ValidatedTlsSessionReplacement<'a, 'store, 'native> {
    frozen: &'a mut FrozenTlsSessionCache<'store>,
    replacement: &'a mut PreparedTlsSessionReplacement,
    _policies: &'a FrozenSessionPolicies<'native>,
}

/// Old native sessions and publication registrations, retired only after unlock.
pub(crate) struct RetiredTlsSessionStore {
    sessions: VecDeque<CachedSession>,
    publications: RetiredTlsTicketPublications,
}

pub(crate) struct RetiredTlsSessionReplacements(Vec<RetiredTlsSessionStore>);
impl RetiredTlsSessionReplacements {
    pub(crate) fn finish(self) -> usize {
        let mut count = 0;
        for retired in self.0 {
            count += retired.finish();
        }
        count
    }
}

fn order_code(order: TicketOrder) -> u8 {
    match order {
        TicketOrder::Newest => 0,
        TicketOrder::OldestConnection => 1,
        TicketOrder::Oldest => 2,
    }
}

fn validate_configuration(
    inner: &CacheInner,
    header: TcpSessionStoreHeader,
) -> Result<(), SessionTransferError> {
    header.validate()?;
    if header.order != order_code(inner.order)
        || usize::from(header.per_hostname) != inner.per_hostname
    {
        return Err(SessionTransferError::Policy);
    }
    Ok(())
}

pub(super) fn validate_arrival(
    previous: impl Iterator<Item = Arrival>,
    arrival: Arrival,
    next_batch: u64,
) -> Result<(), SessionTransferError> {
    if arrival.batch >= next_batch {
        return Err(SessionTransferError::Malformed);
    }
    for old in previous.filter(|old| old.batch == arrival.batch) {
        if arrival.sequence < old.sequence
            || (arrival.sequence == old.sequence && old.sequence != u32::MAX)
        {
            return Err(SessionTransferError::Malformed);
        }
    }
    Ok(())
}

impl TlsSessionOwner {
    pub(crate) fn prepare_replacement(
        &self,
        hostname: Arc<str>,
        header: TcpSessionStoreHeader,
        permits: Vec<SessionImportPermit>,
    ) -> Result<PreparedTlsSessionReplacement, SessionTransferError> {
        validate_hostname(&hostname)?;
        validate_configuration(&self.inner, header)?;
        if permits.len() != header.record_count() {
            return Err(SessionTransferError::Malformed);
        }
        let binding = self
            .inner
            .store
            .lock()
            .map_err(|_| SessionTransferError::Policy)?
            .transfer_binding
            .clone()
            .ok_or(SessionTransferError::Policy)?;
        let mut sessions = VecDeque::new();
        sessions
            .try_reserve_exact(permits.len())
            .map_err(|_| SessionTransferError::Allocation)?;
        let mut previous_ordinal = None;
        for permit in permits {
            let metadata = TcpSessionRecordMetadata::parse(permit.owner_metadata())?;
            if metadata.header != header
                || metadata.hostname != hostname.as_ref()
                || previous_ordinal.is_some_and(|old| metadata.ordinal <= old)
            {
                return Err(SessionTransferError::Malformed);
            }
            let arrival = Arrival {
                batch: metadata.batch,
                sequence: metadata.sequence,
            };
            validate_arrival(
                sessions.iter().map(|cached: &CachedSession| cached.arrival),
                arrival,
                header.next_batch,
            )?;
            previous_ordinal = Some(metadata.ordinal);
            binding.validate_import_permit(&permit, &hostname)?;
            // Conversion can acquire native locks. It occurs before store freezing,
            // and the resulting token is never exposed or attached before commit.
            let session = permit.into_scoped_session()?;
            sessions.push_back(CachedSession {
                hostname: Arc::clone(&hostname),
                session,
                arrival,
            });
        }
        Ok(PreparedTlsSessionReplacement {
            destination: Destination {
                inner: Arc::clone(&self.inner),
                binding,
                hostname,
                header,
            },
            payload: Replacement {
                sessions,
                generation: Arc::new(()),
                next_batch: header.next_batch,
            },
            committed: false,
        })
    }

    /// Prepare storage and retain the actual installed binding before freezing stores.
    pub(crate) fn prepare_capture(
        &self,
        hostname: &str,
        original_index: usize,
    ) -> Result<PreparedTlsSessionCapture, SessionTransferError> {
        validate_hostname(hostname)?;
        let binding = self
            .inner
            .store
            .lock()
            .map_err(|_| SessionTransferError::Policy)?
            .transfer_binding
            .clone()
            .ok_or(SessionTransferError::Policy)?;
        Ok(PreparedTlsSessionCapture {
            owner: TlsSessionOwner {
                inner: Arc::clone(&self.inner),
            },
            binding,
            hostname: Arc::from(hostname),
            original_index,
            records: reserved(MAX_SESSIONS)?,
            header: None,
            attempted: false,
        })
    }

    pub(crate) fn capture_stores(
        inputs: &[(&Self, &str)],
    ) -> Result<Vec<TcpSessionStoreExport>, SessionTransferError> {
        if inputs.len() > MAX_OWNERS {
            return Err(SessionTransferError::TooLarge);
        }
        let mut plans = reserved(inputs.len())?;
        for (index, (owner, hostname)) in inputs.iter().enumerate() {
            plans.push(owner.prepare_capture(hostname, index)?);
        }
        let mut owners = reserved(plans.len())?;
        for (owner, _) in inputs {
            owners.push(*owner);
        }
        let order = Self::ordered_store_indices(&owners)?;
        let mut lock_owners = reserved(owners.len())?;
        for index in order {
            lock_owners.push(TlsSessionOwner {
                inner: Arc::clone(&owners[index].inner),
            });
        }
        plans.sort_unstable_by_key(|plan| Arc::as_ptr(&plan.owner.inner) as usize);
        // Cloned binding handles keep native guards independent of mutable plans.
        let mut policy_bindings = reserved(plans.len())?;
        for plan in &plans {
            policy_bindings.push(plan.binding().clone());
        }
        let mut bindings = reserved(policy_bindings.len())?;
        for binding in &policy_bindings {
            bindings.push(binding);
        }
        let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
        let mut frozen = reserved(plans.len())?;
        let validated = reserved(plans.len())?;
        for owner in &lock_owners {
            frozen.push(owner.freeze_transfer()?);
        }
        let policies = native_plan.try_freeze()?;
        let now = unix_time();
        let result: Result<(), SessionTransferError> = (|| {
            let mut validated = validated;
            let mut total = 0usize;
            for (store, plan) in frozen.iter().zip(&mut plans) {
                let token = store.validate_capture(plan, &policies, now)?;
                total = total
                    .checked_add(token.record_count())
                    .filter(|count| *count <= MAX_RECORDS)
                    .ok_or(SessionTransferError::TooLarge)?;
                validated.push(token);
            }
            // The complete snapshot is checked before the first native up-reference.
            for token in validated {
                token.capture()?;
            }
            Ok(())
        })();
        drop(policies);
        drop(frozen);
        result?;
        plans.sort_unstable_by_key(PreparedTlsSessionCapture::original_index);
        let mut output = reserved(plans.len())?;
        for plan in plans {
            output.push(plan.into_export()?);
        }
        Ok(output)
    }

    pub(crate) fn replace_stores(
        replacements: Vec<PreparedTlsSessionReplacement>,
    ) -> Result<RetiredTlsSessionReplacements, SessionTransferError> {
        if replacements.len() > MAX_OWNERS {
            return Err(SessionTransferError::TooLarge);
        }
        let mut replacements = replacements;
        let mut owners = reserved(replacements.len())?;
        for replacement in &replacements {
            owners.push(replacement.destination_owner());
        }
        let mut owner_refs = reserved(owners.len())?;
        for owner in &owners {
            owner_refs.push(owner);
        }
        let order = Self::ordered_store_indices(&owner_refs)?;
        let mut lock_owners = reserved(owners.len())?;
        for index in order {
            lock_owners.push(TlsSessionOwner {
                inner: Arc::clone(&owners[index].inner),
            });
        }
        replacements.sort_unstable_by_key(|replacement| {
            Arc::as_ptr(&replacement.destination.inner) as usize
        });
        let mut policy_bindings = reserved(replacements.len())?;
        for replacement in &replacements {
            policy_bindings.push(replacement.binding().clone());
        }
        let mut bindings = reserved(policy_bindings.len())?;
        for binding in &policy_bindings {
            bindings.push(binding);
        }
        let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
        // Old native sessions must also outlive store guards during unwinding.
        let mut retired = reserved(replacements.len())?;
        let mut frozen = reserved(replacements.len())?;
        let validated = reserved(replacements.len())?;
        for owner in &lock_owners {
            frozen.push(owner.freeze_transfer()?);
        }
        let policies = native_plan.try_freeze()?;
        let result: Result<(), SessionTransferError> = (|| {
            let mut validated = validated;
            let mut total = 0usize;
            for (store, replacement) in frozen.iter_mut().zip(&mut replacements) {
                let token = store.validate_replacement(replacement, &policies)?;
                total = total
                    .checked_add(token.record_count())
                    .filter(|count| *count <= MAX_RECORDS)
                    .ok_or(SessionTransferError::TooLarge)?;
                validated.push(token);
            }
            // No fallible work or allocation remains after the first store swap.
            for token in validated {
                retired.push(token.commit());
            }
            Ok(())
        })();
        drop(policies);
        drop(frozen);
        result?;
        Ok(RetiredTlsSessionReplacements(retired))
    }
}

impl PreparedTlsSessionCapture {
    pub(crate) fn binding(&self) -> &SessionPolicyBinding {
        &self.binding
    }

    pub(crate) fn original_index(&self) -> usize {
        self.original_index
    }

    /// Consume only after every store/native guard has dropped, including errors.
    pub(crate) fn into_export(self) -> Result<TcpSessionStoreExport, SessionTransferError> {
        let header = self.header.ok_or(SessionTransferError::Policy)?;
        Ok(TcpSessionStoreExport {
            header,
            records: self.records,
        })
    }
}

impl PreparedTlsSessionReplacement {
    pub(crate) fn binding(&self) -> &SessionPolicyBinding {
        &self.destination.binding
    }

    pub(crate) fn destination_owner(&self) -> TlsSessionOwner {
        TlsSessionOwner {
            inner: Arc::clone(&self.destination.inner),
        }
    }
}

impl<'store> FrozenTlsSessionCache<'store> {
    /// Validate the complete physical queue without acquiring native references.
    /// Use one timestamp for every owner in the transaction. Keep the plan alive
    /// until all guards drop even when validation or later capture fails.
    pub(crate) fn validate_capture<'a, 'native>(
        &'a self,
        prepared: &'a mut PreparedTlsSessionCapture,
        policies: &'a FrozenSessionPolicies<'native>,
        now: u64,
    ) -> Result<ValidatedTlsSessionCapture<'a, 'store, 'native>, SessionTransferError> {
        if self.poisoned
            || !std::ptr::eq(self.inner, prepared.owner.inner.as_ref())
            || prepared.attempted
        {
            return Err(SessionTransferError::Policy);
        }
        prepared.attempted = true;
        policies.validate_binding(&prepared.binding, &prepared.hostname)?;
        policies.validate_binding(
            self.store
                .transfer_binding
                .as_ref()
                .ok_or(SessionTransferError::Policy)?,
            &prepared.hostname,
        )?;
        if self.store.sessions.len() > self.inner.per_hostname {
            return Err(SessionTransferError::TooLarge);
        }
        for (index, cached) in self.store.sessions.iter().enumerate() {
            if cached.hostname != prepared.hostname {
                return Err(SessionTransferError::Policy);
            }
            validate_arrival(
                self.store
                    .sessions
                    .iter()
                    .take(index)
                    .map(|cached| cached.arrival),
                cached.arrival,
                self.store.next_batch,
            )?;
        }
        let header = TcpSessionStoreHeader {
            order: order_code(self.inner.order),
            per_hostname: self.inner.per_hostname as u8,
            physical: self.store.sessions.len() as u8,
            records: self
                .store
                .sessions
                .iter()
                .filter(|cached| !is_expired(&cached.session, now))
                .count() as u8,
            next_batch: self.store.next_batch,
        };
        header.validate()?;
        Ok(ValidatedTlsSessionCapture {
            frozen: self,
            prepared,
            _policies: policies,
            header,
            now,
        })
    }

    /// Validate a private prepared import without mutation or allocation.
    pub(crate) fn validate_replacement<'a, 'native>(
        &'a mut self,
        replacement: &'a mut PreparedTlsSessionReplacement,
        policies: &'a FrozenSessionPolicies<'native>,
    ) -> Result<ValidatedTlsSessionReplacement<'a, 'store, 'native>, SessionTransferError> {
        let destination = &replacement.destination;
        let payload = &replacement.payload;
        if self.poisoned
            || !std::ptr::eq(self.inner, destination.inner.as_ref())
            || replacement.committed
        {
            return Err(SessionTransferError::Policy);
        }
        validate_configuration(self.inner, destination.header)?;
        if payload.sessions.len() != destination.header.record_count() {
            return Err(SessionTransferError::Malformed);
        }
        policies.validate_binding(&destination.binding, &destination.hostname)?;
        policies.validate_binding(
            self.store
                .transfer_binding
                .as_ref()
                .ok_or(SessionTransferError::Policy)?,
            &destination.hostname,
        )?;
        for (index, cached) in payload.sessions.iter().enumerate() {
            if cached.hostname != destination.hostname {
                return Err(SessionTransferError::Policy);
            }
            validate_arrival(
                payload
                    .sessions
                    .iter()
                    .take(index)
                    .map(|cached| cached.arrival),
                cached.arrival,
                payload.next_batch,
            )?;
            policies.validate_scoped_session(
                &destination.binding,
                &cached.session,
                &cached.hostname,
            )?;
        }
        Ok(ValidatedTlsSessionReplacement {
            frozen: self,
            replacement,
            _policies: policies,
        })
    }
}

impl ValidatedTlsSessionCapture<'_, '_, '_> {
    pub(crate) fn record_count(&self) -> usize {
        self.header.record_count()
    }

    /// Partial native up-references stay in the plan until the caller unlocks.
    pub(crate) fn capture(self) -> Result<(), SessionTransferError> {
        for (ordinal, cached) in self.frozen.store.sessions.iter().enumerate() {
            if is_expired(&cached.session, self.now) {
                continue;
            }
            self.prepared.records.push(TcpSessionExportRecord {
                pending: self
                    .prepared
                    .binding
                    .prepare_session_export(&cached.session, &cached.hostname)?,
                header: self.header,
                ordinal: ordinal as u8,
                batch: cached.arrival.batch,
                sequence: cached.arrival.sequence,
                hostname: Arc::clone(&cached.hostname),
            });
        }
        self.prepared.header = Some(self.header);
        Ok(())
    }
}

impl ValidatedTlsSessionReplacement<'_, '_, '_> {
    pub(crate) fn record_count(&self) -> usize {
        self.replacement.payload.sessions.len()
    }

    /// No allocation, native destruction or fallible work is allowed here.
    /// Retain the returned old sessions/publications until every guard drops.
    #[must_use]
    pub(crate) fn commit(self) -> RetiredTlsSessionStore {
        let store = &mut self.frozen.store;
        let replacement = self.replacement;
        let payload = &mut replacement.payload;
        std::mem::swap(&mut store.sessions, &mut payload.sessions);
        std::mem::swap(&mut store.generation, &mut payload.generation);
        std::mem::swap(&mut store.next_batch, &mut payload.next_batch);
        store.started = true;
        replacement.committed = true;
        RetiredTlsSessionStore {
            sessions: std::mem::take(&mut payload.sessions),
            publications: RetiredTlsTicketPublications {
                captures: std::mem::take(&mut store.captures),
            },
        }
    }
}

impl RetiredTlsSessionStore {
    pub(crate) fn finish(self) -> usize {
        let count = self.sessions.len();
        drop(self.sessions);
        count + self.publications.finish()
    }
}
