//! One TCP-first, QUIC-second frozen boundary for native ticket transfer.

use btls::ssl::{PreparedSessionPolicyFreeze, SessionImportPermit};
use phantom_quic_btls::{
    FrozenQuicSessionTicketCache, PreparedQuicSessionCapture, PreparedQuicSessionReplacement,
    QuicSessionStoreExport, QuicSessionStoreHeader, QuicSessionTicketCacheOwner,
    RetiredQuicSessionStore, ValidatedQuicSessionReplacement,
};

use super::transfer::{
    PreparedTlsSessionCapture, PreparedTlsSessionReplacement, RetiredTlsSessionStore,
    ValidatedTlsSessionReplacement,
};
use super::*;
use crate::session_tickets::tcp_transfer::{
    MAX_OWNERS, MAX_RECORDS, TcpSessionStoreExport, TcpSessionStoreHeader, reserved,
    validate_hostname,
};

#[derive(Clone, Copy)]
pub(crate) enum MixedSessionOwner<'a> {
    Tcp(&'a TlsSessionOwner),
    Quic(&'a QuicSessionTicketCacheOwner),
}

pub(crate) enum MixedSessionStoreHeader {
    Tcp(TcpSessionStoreHeader),
    Quic(QuicSessionStoreHeader),
}

pub(crate) enum MixedSessionStoreExport {
    Tcp(TcpSessionStoreExport),
    Quic(QuicSessionStoreExport),
}

pub(crate) struct PreparedMixedSessionReplacement<'a> {
    owner: MixedSessionOwner<'a>,
    records: usize,
    replacement: Replacement,
}

enum Replacement {
    Tcp(PreparedTlsSessionReplacement),
    Quic(PreparedQuicSessionReplacement),
}

enum Capture {
    Tcp(PreparedTlsSessionCapture),
    Quic(PreparedQuicSessionCapture),
}

struct CapturePlan<'a> {
    owner: MixedSessionOwner<'a>,
    original_index: usize,
    capture: Capture,
}

enum Frozen<'a> {
    Tcp(FrozenTlsSessionCache<'a>),
    Quic(FrozenQuicSessionTicketCache<'a>),
}

enum Validated<'a, 'store, 'native> {
    Tcp(ValidatedTlsSessionReplacement<'a, 'store, 'native>),
    Quic(ValidatedQuicSessionReplacement<'a, 'store, 'native>),
}

enum Retired {
    Tcp(RetiredTlsSessionStore),
    Quic(RetiredQuicSessionStore),
}

/// Finish after every native/store guard and the facade registry lock drops.
pub(crate) struct RetiredMixedSessionStores(Vec<Retired>);

impl RetiredMixedSessionStores {
    pub(crate) fn finish(self) -> usize {
        self.0
            .into_iter()
            .map(|retired| match retired {
                Retired::Tcp(retired) => retired.finish(),
                Retired::Quic(retired) => retired.finish(),
            })
            .sum()
    }
}

impl<'a> MixedSessionOwner<'a> {
    fn freeze(self) -> Result<Frozen<'a>, SessionTransferError> {
        match self {
            Self::Tcp(owner) => owner.freeze_transfer().map(Frozen::Tcp),
            Self::Quic(owner) => Ok(Frozen::Quic(owner.freeze())),
        }
    }
}

impl MixedSessionStoreExport {
    fn record_count(&self) -> usize {
        match self {
            Self::Tcp(export) => export.header().record_count(),
            Self::Quic(export) => export.header().record_count(),
        }
    }
}

fn check_totals(owners: usize, records: usize) -> Result<(), SessionTransferError> {
    if owners > MAX_OWNERS || records > MAX_RECORDS {
        return Err(SessionTransferError::TooLarge);
    }
    Ok(())
}

/// Uses the same concrete group and private actual-owner order as clear_stores.
/// Unlike clear, transfer rejects aliases instead of silently deduplicating them.
fn owner_order(owners: &[MixedSessionOwner<'_>]) -> Result<Vec<usize>, SessionTransferError> {
    check_totals(owners.len(), 0)?;
    let mut tcp = reserved(owners.len())?;
    let mut quic = reserved(owners.len())?;
    let mut tcp_indices = reserved(owners.len())?;
    let mut quic_indices = reserved(owners.len())?;
    for (index, owner) in owners.iter().enumerate() {
        match owner {
            MixedSessionOwner::Tcp(owner) => {
                tcp.push(*owner);
                tcp_indices.push(index);
            }
            MixedSessionOwner::Quic(owner) => {
                quic.push(*owner);
                quic_indices.push(index);
            }
        }
    }
    let tcp_order = TlsSessionOwner::ordered_store_indices(&tcp)?;
    let quic_order = QuicSessionTicketCacheOwner::ordered_store_indices(&quic)?;
    let mut order = reserved(owners.len())?;
    order.extend(tcp_order.into_iter().map(|index| tcp_indices[index]));
    order.extend(quic_order.into_iter().map(|index| quic_indices[index]));
    Ok(order)
}

/// Capture published stores without consuming them, returning original input order.
/// Native sealing and the combined 16 MiB envelope check happen after this returns.
pub(crate) fn capture_stores(
    inputs: &[(MixedSessionOwner<'_>, &str)],
) -> Result<Vec<MixedSessionStoreExport>, SessionTransferError> {
    check_totals(inputs.len(), 0)?;
    let mut owners = reserved(inputs.len())?;
    for (owner, hostname) in inputs {
        validate_hostname(hostname)?;
        owners.push(*owner);
    }
    let order = owner_order(&owners)?;
    let mut unsorted = reserved(inputs.len())?;
    let mut quic_inputs = reserved(inputs.len())?;
    let mut quic_indices = reserved(inputs.len())?;
    for (index, (owner, hostname)) in inputs.iter().enumerate() {
        match owner {
            MixedSessionOwner::Tcp(owner) => {
                unsorted.push(Some(Capture::Tcp(owner.prepare_capture(hostname, index)?)))
            }
            MixedSessionOwner::Quic(owner) => {
                unsorted.push(None);
                quic_inputs.push((*owner, *hostname));
                quic_indices.push(index);
            }
        }
    }
    // One batch preserves QUIC's aggregate remembered-parameter preparation bound.
    for plan in QuicSessionTicketCacheOwner::prepare_captures(&quic_inputs)? {
        let index = quic_indices[plan.original_index()];
        unsorted[index] = Some(Capture::Quic(plan));
    }
    let mut plans = reserved(inputs.len())?;
    for index in order {
        plans.push(CapturePlan {
            owner: owners[index],
            original_index: index,
            capture: unsorted[index].take().ok_or(SessionTransferError::Policy)?,
        });
    }
    let mut policy_bindings = reserved(plans.len())?;
    for plan in &plans {
        policy_bindings.push(match &plan.capture {
            Capture::Tcp(plan) => plan.binding().clone(),
            Capture::Quic(plan) => plan.binding().clone(),
        });
    }
    let mut bindings = reserved(policy_bindings.len())?;
    for binding in &policy_bindings {
        bindings.push(binding);
    }
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let mut output = reserved(plans.len())?;
    let mut frozen = reserved(plans.len())?;
    for plan in &plans {
        frozen.push(plan.owner.freeze()?);
    }
    let policies = native_plan.try_freeze()?;
    let now = unix_time();
    let result: Result<(), SessionTransferError> = (|| {
        for (store, plan) in frozen.iter().zip(&mut plans) {
            match (store, &mut plan.capture) {
                (Frozen::Tcp(store), Capture::Tcp(plan)) => {
                    store.validate_capture(plan, &policies, now)?.capture()?;
                }
                (Frozen::Quic(store), Capture::Quic(plan)) => {
                    store.capture(plan, &policies)?;
                }
                _ => return Err(SessionTransferError::Policy),
            }
        }
        Ok(())
    })();
    drop(policies);
    drop(frozen);
    // Partial native up-references stay in plans until all guards have dropped.
    result?;
    plans.sort_unstable_by_key(|plan| plan.original_index);
    let mut total = 0usize;
    for plan in plans {
        let export = match plan.capture {
            Capture::Tcp(plan) => MixedSessionStoreExport::Tcp(plan.into_export()?),
            Capture::Quic(plan) => MixedSessionStoreExport::Quic(plan.into_export()?),
        };
        total = total
            .checked_add(export.record_count())
            .ok_or(SessionTransferError::TooLarge)?;
        check_totals(inputs.len(), total)?;
        output.push(export);
    }
    Ok(output)
}

impl<'a> PreparedMixedSessionReplacement<'a> {
    /// The caller authenticates manifests and witnesses before native authorization.
    /// All native conversion and private allocation precede transaction freezing.
    pub(crate) fn new(
        owner: MixedSessionOwner<'a>,
        hostname: Arc<str>,
        header: MixedSessionStoreHeader,
        permits: Vec<SessionImportPermit>,
    ) -> Result<Self, SessionTransferError> {
        let records = permits.len();
        check_totals(1, records)?;
        let replacement = match (owner, header) {
            (MixedSessionOwner::Tcp(owner), MixedSessionStoreHeader::Tcp(header)) => {
                Replacement::Tcp(owner.prepare_replacement(hostname, header, permits)?)
            }
            (MixedSessionOwner::Quic(owner), MixedSessionStoreHeader::Quic(header)) => {
                Replacement::Quic(owner.prepare_replacement(hostname, header, permits)?)
            }
            _ => return Err(SessionTransferError::Policy),
        };
        Ok(Self {
            owner,
            records,
            replacement,
        })
    }
}

/// Validate all destinations under one native freeze, then swap without failure.
/// The caller swaps its prepared cold registry before dropping returned retirement.
pub(crate) fn replace_stores(
    replacements: Vec<PreparedMixedSessionReplacement<'_>>,
) -> Result<RetiredMixedSessionStores, SessionTransferError> {
    check_totals(replacements.len(), 0)?;
    let mut owners = reserved(replacements.len())?;
    let mut records = 0usize;
    for replacement in &replacements {
        records = records
            .checked_add(replacement.records)
            .ok_or(SessionTransferError::TooLarge)?;
        check_totals(replacements.len(), records)?;
        owners.push(replacement.owner);
    }
    let order = owner_order(&owners)?;
    let mut unsorted = reserved(replacements.len())?;
    unsorted.extend(replacements.into_iter().map(Some));
    let mut replacements = reserved(unsorted.len())?;
    for index in order {
        replacements.push(unsorted[index].take().ok_or(SessionTransferError::Policy)?);
    }
    let mut policy_bindings = reserved(replacements.len())?;
    for replacement in &replacements {
        policy_bindings.push(match &replacement.replacement {
            Replacement::Tcp(plan) => plan.binding().clone(),
            Replacement::Quic(plan) => plan.binding().clone(),
        });
    }
    let mut bindings = reserved(policy_bindings.len())?;
    for binding in &policy_bindings {
        bindings.push(binding);
    }
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    // Declared before guards so unwinding cannot destroy old sessions under locks.
    let mut retired = reserved(replacements.len())?;
    let mut frozen = reserved(replacements.len())?;
    let validated = reserved(replacements.len())?;
    for replacement in &replacements {
        frozen.push(replacement.owner.freeze()?);
    }
    let policies = native_plan.try_freeze()?;
    let result: Result<(), SessionTransferError> = (|| {
        let mut validated = validated;
        for (store, replacement) in frozen.iter_mut().zip(&mut replacements) {
            validated.push(match (store, &mut replacement.replacement) {
                (Frozen::Tcp(store), Replacement::Tcp(plan)) => {
                    Validated::Tcp(store.validate_replacement(plan, &policies)?)
                }
                (Frozen::Quic(store), Replacement::Quic(plan)) => {
                    Validated::Quic(store.validate_replacement(plan, &policies)?)
                }
                _ => return Err(SessionTransferError::Policy),
            });
        }
        // All borrowed validation succeeds before the first infallible store swap.
        for token in validated {
            retired.push(match token {
                Validated::Tcp(token) => Retired::Tcp(token.commit()),
                Validated::Quic(token) => Retired::Quic(token.commit()),
            });
        }
        Ok(())
    })();
    drop(policies);
    drop(frozen);
    result?;
    Ok(RetiredMixedSessionStores(retired))
}

#[cfg(test)]
mod tests;
