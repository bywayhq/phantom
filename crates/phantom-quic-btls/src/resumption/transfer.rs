//! Preallocated QUIC store primitives for one heterogeneous transaction.

use btls::ssl::{
    AuthenticatedSessionRecord, FrozenSessionPolicies, PendingSessionExport, SessionImportPermit,
    SslVersion,
};
use quinn_proto::transport_parameters::TransportParameters;

use super::*;

mod metadata;
pub use metadata::{QuicSessionRecordMetadata, QuicSessionStoreHeader};

const MAX_OWNERS: usize = 256;
const MAX_PARAMETERS: usize = u16::MAX as usize;
const MAX_CAPTURE_PARAMETER_BYTES: usize = 16 * 1024 * 1024;

fn reserved<T>(count: usize) -> Result<Vec<T>, SessionTransferError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| SessionTransferError::Allocation)?;
    Ok(values)
}

fn copy(bytes: &[u8]) -> Result<Box<[u8]>, SessionTransferError> {
    let mut value = reserved(bytes.len())?;
    value.extend_from_slice(bytes);
    Ok(value.into_boxed_slice())
}

fn validate_hostname(name: &str) -> Result<(), SessionTransferError> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() || name.as_bytes().contains(&0) {
        return Err(SessionTransferError::Malformed);
    }
    Ok(())
}

fn validate_parameters(
    version: QuicVersion,
    value: Option<&[u8]>,
) -> Result<(), SessionTransferError> {
    if let Some(value) = value {
        if value.len() > MAX_PARAMETERS {
            return Err(SessionTransferError::TooLarge);
        }
        TransportParameters::validate_remembered_server(value, version.wire())
            .map_err(|_| SessionTransferError::Malformed)?;
    }
    Ok(())
}

fn validate_ticket(ticket: &ResumptionTicket) -> Result<(), SessionTransferError> {
    if ticket.session.protocol_version() != SslVersion::TLS1_3
        || !ticket.session.should_be_single_use()
    {
        return Err(SessionTransferError::Policy);
    }
    if ticket
        .application_state
        .as_ref()
        .is_some_and(|value| value.len() > MAX_APPLICATION_STATE_LEN)
    {
        return Err(SessionTransferError::TooLarge);
    }
    validate_parameters(ticket.version, ticket.peer_transport_parameters.as_deref())
}

struct CaptureSlot {
    pending: Option<PendingSessionExport>,
    ordinal: u8,
    version: QuicVersion,
    parameters: Vec<u8>,
    parameters_present: bool,
    application: Option<Arc<[u8]>>,
}

/// Preallocated capture buffers and the actual installed native binding.
/// Keep this plan alive until every store/native guard drops, including errors.
pub struct PreparedQuicSessionCapture {
    inner: Arc<CacheOwner>,
    binding: SessionPolicyBinding,
    hostname: Arc<str>,
    original_index: usize,
    slots: Vec<CaptureSlot>,
    header: Option<QuicSessionStoreHeader>,
    attempted: bool,
}

/// A native-proven up-reference plus closed source metadata, never attachable.
pub struct QuicSessionExportRecord {
    pending: PendingSessionExport,
    header: QuicSessionStoreHeader,
    ordinal: u8,
    version: QuicVersion,
    hostname: Arc<str>,
    parameters: Option<Vec<u8>>,
    application: Option<Arc<[u8]>>,
}

/// A complete published-queue snapshot, including explicit empty intent.
pub struct QuicSessionStoreExport {
    header: QuicSessionStoreHeader,
    records: Vec<QuicSessionExportRecord>,
}

/// Private imported sessions prepared before any transaction store locks.
/// Retain the plan until all transaction guards drop, including on validation errors.
pub struct PreparedQuicSessionReplacement {
    inner: Arc<CacheOwner>,
    binding: SessionPolicyBinding,
    hostname: Arc<str>,
    header: QuicSessionStoreHeader,
    payload: Replacement,
    committed: bool,
}

struct Replacement {
    sessions: VecDeque<CachedSession>,
    round_trip_times: VecDeque<(Box<str>, Duration)>,
    generation: Arc<()>,
}

/// A successful validation tied to the exact frozen store and native guards.
/// Hold every transaction's validated token before committing any of them.
pub struct ValidatedQuicSessionReplacement<'a, 'store, 'native> {
    frozen: &'a mut FrozenQuicSessionTicketCache<'store>,
    replacement: &'a mut PreparedQuicSessionReplacement,
    _policies: &'a FrozenSessionPolicies<'native>,
}

/// Old queues and publications; finish after all transaction guards drop.
pub struct RetiredQuicSessionStore {
    sessions: VecDeque<CachedSession>,
    round_trip_times: VecDeque<(Box<str>, Duration)>,
    publications: RetiredQuicTicketPublications,
}

impl QuicSessionTicketCacheOwner {
    /// Prepare captures in private cache-lock order, rejecting duplicate aliases.
    /// Each plan's original index maps back to `inputs` without exposing identity.
    /// The coordinator must use this order consistently for capture, import and clear.
    /// Concurrent parameter growth returns `Busy` at capture; prepare a new batch.
    pub fn prepare_captures(
        inputs: &[(&Self, &str)],
    ) -> Result<Vec<PreparedQuicSessionCapture>, SessionTransferError> {
        if inputs.len() > MAX_OWNERS {
            return Err(SessionTransferError::TooLarge);
        }
        let mut owners = reserved(inputs.len())?;
        for (owner, name) in inputs {
            validate_hostname(name)?;
            owners.push(*owner);
        }
        let order = Self::ordered_store_indices(&owners)?;
        let mut plans = reserved(owners.len())?;
        let mut parameter_bytes = 0usize;
        for index in order {
            let (owner, name) = inputs[index];
            let (binding, lengths) = {
                let state = owner
                    .inner
                    .state
                    .lock()
                    .map_err(|_| SessionTransferError::Policy)?;
                if state.sessions.len() > MAX_SESSIONS {
                    return Err(SessionTransferError::Malformed);
                }
                let binding = state
                    .transfer_binding
                    .clone()
                    .ok_or(SessionTransferError::Policy)?;
                let mut lengths = [0usize; MAX_SESSIONS];
                for (slot, cached) in state.sessions.iter().enumerate() {
                    lengths[slot] = cached
                        .ticket
                        .peer_transport_parameters
                        .as_ref()
                        .map_or(0, |value| value.len());
                    if lengths[slot] > MAX_PARAMETERS {
                        return Err(SessionTransferError::TooLarge);
                    }
                }
                (binding, lengths)
            };
            let mut slots = reserved(MAX_SESSIONS)?;
            for length in lengths {
                parameter_bytes = parameter_bytes
                    .checked_add(length)
                    .filter(|n| *n <= MAX_CAPTURE_PARAMETER_BYTES)
                    .ok_or(SessionTransferError::TooLarge)?;
                slots.push(CaptureSlot {
                    pending: None,
                    ordinal: 0,
                    version: QuicVersion::V1,
                    parameters: reserved(length)?,
                    parameters_present: false,
                    application: None,
                });
            }
            plans.push(PreparedQuicSessionCapture {
                inner: Arc::clone(&owner.inner),
                binding,
                hostname: Arc::from(name),
                original_index: index,
                slots,
                header: None,
                attempted: false,
            });
        }
        Ok(plans)
    }

    /// Consume genuine permits privately after complete metadata/protocol checks.
    /// The facade validates owner manifests, witnesses and application semantics first.
    pub fn prepare_replacement(
        &self,
        hostname: Arc<str>,
        header: QuicSessionStoreHeader,
        permits: Vec<SessionImportPermit>,
    ) -> Result<PreparedQuicSessionReplacement, SessionTransferError> {
        validate_hostname(&hostname)?;
        if permits.len() != header.record_count() {
            return Err(SessionTransferError::Malformed);
        }
        let binding = self
            .inner
            .state
            .lock()
            .map_err(|_| SessionTransferError::Policy)?
            .transfer_binding
            .clone()
            .ok_or(SessionTransferError::Policy)?;
        let mut metadata = reserved(permits.len())?;
        for permit in &permits {
            metadata.push(QuicSessionRecordMetadata::parse(permit.owner_metadata())?);
        }
        metadata::validate_store(header, &hostname, &metadata)?;
        let mut tickets = reserved(metadata.len())?;
        for (shape, permit) in metadata.iter().zip(&permits) {
            shape.validate_transport_parameters()?;
            binding.validate_import_permit(permit, &hostname)?;
            let parameters = shape.peer_transport_parameters.map(copy).transpose()?;
            let application = shape.application_state.map(Arc::<[u8]>::from);
            tickets.push((shape.version, parameters, application));
        }
        drop(metadata);
        let mut sessions = VecDeque::new();
        sessions
            .try_reserve_exact(permits.len())
            .map_err(|_| SessionTransferError::Allocation)?;
        for (permit, (version, peer_transport_parameters, application_state)) in
            permits.into_iter().zip(tickets)
        {
            let session = permit.into_scoped_session()?;
            // These are actual native attributes of the authorized private session.
            if session.protocol_version() != SslVersion::TLS1_3 || !session.should_be_single_use() {
                return Err(SessionTransferError::Policy);
            }
            sessions.push_back(CachedSession {
                server_name: hostname.as_ref().into(),
                ticket: ResumptionTicket {
                    session: Arc::new(session),
                    version,
                    peer_transport_parameters,
                    application_state,
                },
            });
        }
        let mut times = VecDeque::new();
        if let Some(rtt) = header.round_trip_time() {
            times
                .try_reserve_exact(1)
                .map_err(|_| SessionTransferError::Allocation)?;
            times.push_back((hostname.as_ref().into(), rtt));
        }
        Ok(PreparedQuicSessionReplacement {
            inner: Arc::clone(&self.inner),
            binding,
            hostname,
            header,
            payload: Replacement {
                sessions,
                round_trip_times: times,
                generation: Arc::new(()),
            },
            committed: false,
        })
    }
}

impl PreparedQuicSessionCapture {
    /// Actual installed binding, borrowed only to prepare the shared native freeze.
    #[must_use]
    pub fn binding(&self) -> &SessionPolicyBinding {
        &self.binding
    }
    /// Original owner input index in the internally sorted preparation batch.
    #[must_use]
    pub fn original_index(&self) -> usize {
        self.original_index
    }
    /// Move captured records out only after every store/native guard drops.
    pub fn into_export(self) -> Result<QuicSessionStoreExport, SessionTransferError> {
        let header = self.header.ok_or(SessionTransferError::Policy)?;
        let mut records = reserved(header.record_count())?;
        for slot in self.slots {
            if let Some(pending) = slot.pending {
                records.push(QuicSessionExportRecord {
                    pending,
                    header,
                    ordinal: slot.ordinal,
                    version: slot.version,
                    hostname: Arc::clone(&self.hostname),
                    parameters: slot.parameters_present.then_some(slot.parameters),
                    application: slot.application,
                });
            }
        }
        Ok(QuicSessionStoreExport { header, records })
    }
}

impl FrozenQuicSessionTicketCache<'_> {
    /// Capture all published records nonconsumingly under shared native guards.
    /// On error keep `plan` alive until all guards drop; partial native references
    /// are retained inside it. Uncommitted ApplicationState-held tickets are excluded.
    pub fn capture(
        &self,
        plan: &mut PreparedQuicSessionCapture,
        policies: &FrozenSessionPolicies<'_>,
    ) -> Result<(), SessionTransferError> {
        if self.poisoned || !std::ptr::eq(self.inner, plan.inner.as_ref()) || plan.attempted {
            return Err(SessionTransferError::Policy);
        }
        plan.attempted = true;
        policies.validate_binding(&plan.binding, &plan.hostname)?;
        policies.validate_binding(
            self.state
                .transfer_binding
                .as_ref()
                .ok_or(SessionTransferError::Policy)?,
            &plan.hostname,
        )?;
        if self.state.sessions.len() > MAX_SESSIONS || self.state.round_trip_times.len() > 1 {
            return Err(SessionTransferError::Malformed);
        }
        for (name, _) in &self.state.round_trip_times {
            if name.as_ref() != plan.hostname.as_ref() {
                return Err(SessionTransferError::Policy);
            }
        }
        let now = unix_time();
        let count = self
            .state
            .sessions
            .iter()
            .filter(|entry| !is_expired(&entry.ticket.session, now))
            .count();
        let header = QuicSessionStoreHeader::new(
            self.state.sessions.len(),
            count,
            self.state.round_trip_times.back().map(|(_, rtt)| *rtt),
        )?;
        // Validate the complete physical owner before obtaining any native reference.
        for (ordinal, cached) in self.state.sessions.iter().enumerate() {
            if cached.server_name.as_ref() != plan.hostname.as_ref() {
                return Err(SessionTransferError::Policy);
            }
            validate_ticket(&cached.ticket)?;
            if cached
                .ticket
                .peer_transport_parameters
                .as_ref()
                .is_some_and(|parameters| {
                    parameters.len() > plan.slots[ordinal].parameters.capacity()
                })
            {
                return Err(SessionTransferError::Busy);
            }
        }
        for (ordinal, cached) in self.state.sessions.iter().enumerate() {
            if is_expired(&cached.ticket.session, now) {
                continue;
            }
            let pending = plan
                .binding
                .prepare_session_export(&cached.ticket.session, &cached.server_name)?;
            let slot = &mut plan.slots[ordinal];
            slot.pending = Some(pending);
            slot.ordinal = ordinal as u8;
            slot.version = cached.ticket.version;
            if let Some(parameters) = &cached.ticket.peer_transport_parameters {
                slot.parameters_present = true;
                slot.parameters.extend_from_slice(parameters);
            }
            slot.application = cached.ticket.application_state.clone();
        }
        plan.header = Some(header);
        Ok(())
    }
}

impl<'store> FrozenQuicSessionTicketCache<'store> {
    /// Validate without mutation or allocation while all transaction guards remain held.
    pub fn validate_replacement<'a, 'native>(
        &'a mut self,
        replacement: &'a mut PreparedQuicSessionReplacement,
        policies: &'a FrozenSessionPolicies<'native>,
    ) -> Result<ValidatedQuicSessionReplacement<'a, 'store, 'native>, SessionTransferError> {
        if self.poisoned
            || !std::ptr::eq(self.inner, replacement.inner.as_ref())
            || replacement.committed
        {
            return Err(SessionTransferError::Policy);
        }
        policies.validate_binding(&replacement.binding, &replacement.hostname)?;
        policies.validate_binding(
            self.state
                .transfer_binding
                .as_ref()
                .ok_or(SessionTransferError::Policy)?,
            &replacement.hostname,
        )?;
        if replacement.payload.sessions.len() != replacement.header.record_count() {
            return Err(SessionTransferError::Malformed);
        }
        for cached in &replacement.payload.sessions {
            if cached.server_name.as_ref() != replacement.hostname.as_ref() {
                return Err(SessionTransferError::Policy);
            }
            validate_ticket(&cached.ticket)?;
            policies.validate_scoped_session(
                &replacement.binding,
                &cached.ticket.session,
                &cached.server_name,
            )?;
        }
        Ok(ValidatedQuicSessionReplacement {
            frozen: self,
            replacement,
            _policies: policies,
        })
    }
}

impl PreparedQuicSessionReplacement {
    /// Actual installed binding, borrowed only to prepare the shared native freeze.
    #[must_use]
    pub fn binding(&self) -> &SessionPolicyBinding {
        &self.binding
    }
}

impl ValidatedQuicSessionReplacement<'_, '_, '_> {
    /// Infallibly swap prevalidated queues, RTT and generation without destruction.
    /// Retain the returned cleanup until all transaction guards have dropped.
    #[must_use]
    pub fn commit(self) -> RetiredQuicSessionStore {
        let state = &mut self.frozen.state;
        let payload = &mut self.replacement.payload;
        std::mem::swap(&mut state.sessions, &mut payload.sessions);
        std::mem::swap(&mut state.round_trip_times, &mut payload.round_trip_times);
        std::mem::swap(&mut state.generation, &mut payload.generation);
        state.started = true;
        self.replacement.committed = true;
        RetiredQuicSessionStore {
            sessions: std::mem::take(&mut payload.sessions),
            round_trip_times: std::mem::take(&mut payload.round_trip_times),
            publications: RetiredQuicTicketPublications {
                generation: std::mem::replace(
                    &mut payload.generation,
                    Arc::clone(&state.generation),
                ),
                application_states: std::mem::take(&mut state.application_states),
            },
        }
    }
}

impl RetiredQuicSessionStore {
    /// Destroy old sessions and retire held application publication after unlock.
    #[must_use]
    pub fn finish(self) -> usize {
        let count = self.sessions.len();
        drop(self.sessions);
        drop(self.round_trip_times);
        count + self.publications.finish()
    }
}

impl QuicSessionStoreExport {
    /// Complete captured shape and latest RTT, including empty replacement intent.
    #[must_use]
    pub fn header(&self) -> QuicSessionStoreHeader {
        self.header
    }
    /// Native-proven records in original oldest-to-newest relative order.
    #[must_use]
    pub fn into_records(self) -> Vec<QuicSessionExportRecord> {
        self.records
    }
}

impl QuicSessionExportRecord {
    /// Original physical slot, preserving gaps from expired source entries.
    #[must_use]
    pub fn ordinal(&self) -> usize {
        usize::from(self.ordinal)
    }
    /// Application state for the actual protocol consumer's validation.
    #[must_use]
    pub fn application_state(&self) -> Option<&[u8]> {
        self.application.as_deref()
    }
    /// Seal complete owner metadata after every native/store guard is released.
    pub fn seal(
        self,
        payload: &[u8],
        key: &[u8; 32],
    ) -> Result<AuthenticatedSessionRecord, SessionTransferError> {
        let metadata = QuicSessionRecordMetadata::new(
            self.header,
            usize::from(self.ordinal),
            &self.hostname,
            self.version,
            self.parameters.as_deref(),
            self.application.as_deref(),
            payload,
        )?;
        let bytes = metadata.to_bytes()?;
        self.pending.seal(&bytes, key)
    }
}

macro_rules! redacted_debug {
    ($($kind:ty),+ $(,)?) => { $(impl std::fmt::Debug for $kind {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct(stringify!($kind)).finish_non_exhaustive()
        }
    })+ };
}
redacted_debug!(
    PreparedQuicSessionCapture,
    PreparedQuicSessionReplacement,
    QuicSessionExportRecord,
    QuicSessionStoreExport,
    RetiredQuicSessionStore,
    ValidatedQuicSessionReplacement<'_, '_, '_>
);

#[cfg(test)]
mod tests;
