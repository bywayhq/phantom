//! Bounded native-backed capture and complete TCP store replacement.

use btls::ssl::{PreparedSessionPolicyFreeze, SessionImportPermit};

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
}

struct Replacement {
    sessions: VecDeque<CachedSession>,
    generation: Arc<()>,
    next_batch: u64,
}

struct RetiredStore {
    sessions: VecDeque<CachedSession>,
    publications: RetiredTlsTicketPublications,
}

pub(crate) struct RetiredTlsSessionReplacements(Vec<Option<RetiredStore>>);
impl RetiredTlsSessionReplacements {
    pub(crate) fn finish(self) -> usize {
        let mut count = 0;
        for retired in self.0.into_iter().flatten() {
            count += retired.sessions.len();
            drop(retired.sessions);
            count += retired.publications.finish();
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
        })
    }

    pub(crate) fn capture_stores(
        inputs: &[(&Self, &str)],
    ) -> Result<Vec<TcpSessionStoreExport>, SessionTransferError> {
        if inputs.len() > MAX_OWNERS {
            return Err(SessionTransferError::TooLarge);
        }
        let mut destinations = reserved(inputs.len())?;
        let mut buffers = reserved(inputs.len())?;
        for (input_index, (owner, hostname)) in inputs.iter().enumerate() {
            validate_hostname(hostname)?;
            let binding = owner
                .inner
                .store
                .lock()
                .map_err(|_| SessionTransferError::Policy)?
                .transfer_binding
                .clone()
                .ok_or(SessionTransferError::Policy)?;
            destinations.push((input_index, &owner.inner, binding, *hostname));
            buffers.push(reserved(MAX_SESSIONS)?);
        }
        destinations.sort_unstable_by_key(|(_, inner, _, _)| Arc::as_ptr(inner) as usize);
        if destinations
            .windows(2)
            .any(|pair| Arc::ptr_eq(pair[0].1, pair[1].1))
        {
            return Err(SessionTransferError::Policy);
        }
        let mut bindings = reserved(destinations.len())?;
        for (_, _, binding, _) in &destinations {
            bindings.push(binding);
        }
        let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
        let mut frozen = reserved(destinations.len())?;
        let mut exports = reserved(destinations.len())?;
        for (_, inner, _, _) in &destinations {
            frozen.push(
                inner
                    .store
                    .lock()
                    .map_err(|_| SessionTransferError::Policy)?,
            );
        }
        let policies = native_plan.try_freeze()?;
        let now = unix_time();
        let result: Result<(), SessionTransferError> = (|| {
            let mut total = 0usize;
            // Inspect the entire snapshot before capturing a native reference.
            for ((_, inner, binding, hostname), store) in destinations.iter().zip(&frozen) {
                policies.validate_binding(binding, hostname)?;
                policies.validate_binding(
                    store
                        .transfer_binding
                        .as_ref()
                        .ok_or(SessionTransferError::Policy)?,
                    hostname,
                )?;
                if store.sessions.len() > inner.per_hostname {
                    return Err(SessionTransferError::TooLarge);
                }
                for (index, cached) in store.sessions.iter().enumerate() {
                    if cached.hostname.as_ref() != *hostname {
                        return Err(SessionTransferError::Policy);
                    }
                    validate_arrival(
                        store
                            .sessions
                            .iter()
                            .take(index)
                            .map(|cached| cached.arrival),
                        cached.arrival,
                        store.next_batch,
                    )?;
                }
                let count = store
                    .sessions
                    .iter()
                    .filter(|cached| !is_expired(&cached.session, now))
                    .count();
                total = total
                    .checked_add(count)
                    .ok_or(SessionTransferError::TooLarge)?;
                if total > MAX_RECORDS {
                    return Err(SessionTransferError::TooLarge);
                }
            }
            for (((input_index, inner, binding, _), store), records) in
                destinations.iter().zip(&frozen).zip(&mut buffers)
            {
                let header = TcpSessionStoreHeader {
                    order: order_code(inner.order),
                    per_hostname: inner.per_hostname as u8,
                    physical: store.sessions.len() as u8,
                    records: store
                        .sessions
                        .iter()
                        .filter(|cached| !is_expired(&cached.session, now))
                        .count() as u8,
                    next_batch: store.next_batch,
                };
                header.validate()?;
                for (ordinal, cached) in store.sessions.iter().enumerate() {
                    if is_expired(&cached.session, now) {
                        continue;
                    }
                    records.push(TcpSessionExportRecord {
                        pending: binding
                            .prepare_session_export(&cached.session, &cached.hostname)?,
                        header,
                        ordinal: ordinal as u8,
                        batch: cached.arrival.batch,
                        sequence: cached.arrival.sequence,
                        hostname: Arc::clone(&cached.hostname),
                    });
                }
                exports.push((*input_index, header));
            }
            Ok(())
        })();
        // Pending up-references may have native destructors. Keep them in buffers
        // until every native and store guard is released, including error paths.
        drop(policies);
        drop(frozen);
        result?;
        let mut output = reserved(exports.len())?;
        for ((input_index, header), records) in exports.into_iter().zip(buffers) {
            output.push((input_index, TcpSessionStoreExport { header, records }));
        }
        output.sort_unstable_by_key(|(index, _)| *index);
        let mut values = reserved(output.len())?;
        for (_, export) in output {
            values.push(export);
        }
        Ok(values)
    }

    pub(crate) fn replace_stores(
        replacements: Vec<PreparedTlsSessionReplacement>,
    ) -> Result<RetiredTlsSessionReplacements, SessionTransferError> {
        if replacements.len() > MAX_OWNERS {
            return Err(SessionTransferError::TooLarge);
        }
        let mut replacements = replacements;
        replacements.sort_unstable_by_key(|replacement| {
            Arc::as_ptr(&replacement.destination.inner) as usize
        });
        if replacements
            .windows(2)
            .any(|pair| Arc::ptr_eq(&pair[0].destination.inner, &pair[1].destination.inner))
        {
            return Err(SessionTransferError::Policy);
        }
        let mut destinations = reserved(replacements.len())?;
        let mut payloads = reserved(replacements.len())?;
        let mut retired = reserved(replacements.len())?;
        for replacement in replacements {
            destinations.push(replacement.destination);
            payloads.push(replacement.payload);
            retired.push(None);
        }
        let mut bindings = reserved(destinations.len())?;
        for destination in &destinations {
            bindings.push(&destination.binding);
        }
        let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
        let mut frozen = reserved(destinations.len())?;
        for destination in &destinations {
            frozen.push(
                destination
                    .inner
                    .store
                    .lock()
                    .map_err(|_| SessionTransferError::Policy)?,
            );
        }
        let policies = native_plan.try_freeze()?;
        let result: Result<(), SessionTransferError> = (|| {
            let mut total = 0usize;
            for ((destination, payload), store) in destinations.iter().zip(&payloads).zip(&frozen) {
                validate_configuration(&destination.inner, destination.header)?;
                if payload.sessions.len() != destination.header.record_count() {
                    return Err(SessionTransferError::Malformed);
                }
                total = total
                    .checked_add(payload.sessions.len())
                    .ok_or(SessionTransferError::TooLarge)?;
                if total > MAX_RECORDS {
                    return Err(SessionTransferError::TooLarge);
                }
                policies.validate_binding(&destination.binding, &destination.hostname)?;
                policies.validate_binding(
                    store
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
            }
            // Every fallible operation has finished. These swaps cannot allocate
            // or destroy old native sessions while any store/native guard is held.
            for ((store, payload), cleanup) in
                frozen.iter_mut().zip(&mut payloads).zip(&mut retired)
            {
                std::mem::swap(&mut store.sessions, &mut payload.sessions);
                std::mem::swap(&mut store.generation, &mut payload.generation);
                std::mem::swap(&mut store.next_batch, &mut payload.next_batch);
                store.started = true;
                *cleanup = Some(RetiredStore {
                    sessions: std::mem::take(&mut payload.sessions),
                    publications: RetiredTlsTicketPublications {
                        captures: std::mem::take(&mut store.captures),
                    },
                });
            }
            Ok(())
        })();
        drop(policies);
        drop(frozen);
        result?;
        Ok(RetiredTlsSessionReplacements(retired))
    }
}
