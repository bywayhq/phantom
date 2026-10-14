//! Authenticated native session custody. Policy bytes come from the configuration owner.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

use foreign_types::ForeignTypeRef;
use zeroize::Zeroizing;

use super::{
    ScopedSslSession, SessionPublication, SessionVerifierProvenance, SslContext, SslContextRef,
    SslSession, SslSessionScope, SslVersion,
};
use crate::aead::ConcurrentAeadCtx;
use crate::error::ErrorStack;
use crate::hash::{hash, hmac_sha256, MessageDigest};

const MAX_POLICY: usize = 1024 * 1024;
const MAX_CREDENTIAL: usize = 64 * 1024;
const MAX_METADATA: usize = 128 * 1024;
const MAX_SESSION: usize = 256 * 1024;
const MAX_RECORDS: usize = 2560;
const MAX_ENVELOPE: usize = 16 * 1024 * 1024;
const HEADER: usize = 56;
const TAG: usize = 16;
const MAGIC: &[u8; 8] = b"PHTKT001";
const BACKEND: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    ":boringssl:f1f2556a5dfa59e147d9d47279cc3f7f8a18b433:transfer1"
);

/// A bounded preparation, authentication or compatibility failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionTransferError {
    /// A named library allocation limit was exceeded.
    TooLarge,
    /// Bounded buffer allocation failed.
    Allocation,
    /// The cryptographic or native session backend failed.
    Backend(ErrorStack),
    /// Envelope or record framing is invalid.
    Malformed,
    /// Snapshot authentication failed.
    Authentication,
    /// The compiled backend or transfer format differs.
    IncompatibleBackend,
    /// The native session has expired.
    Expired,
    /// Native default peer authentication has not been established.
    Unauthenticated,
    /// Installed policy is absent, changed or belongs to another scope or peer.
    Policy,
    /// A context or scope policy lock is currently held.
    Busy,
    /// Configured credential contents differ.
    Credentials,
    /// A transaction-local record has already issued its permit.
    Consumed,
}

impl fmt::Display for SessionTransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "session transfer exceeds a library resource limit",
            Self::Allocation => "session transfer allocation failed",
            Self::Backend(_) => "session transfer backend failed",
            Self::Malformed => "invalid session transfer framing",
            Self::Authentication => "session transfer authentication failed",
            Self::IncompatibleBackend => "incompatible session transfer backend",
            Self::Expired => "session transfer record has expired",
            Self::Unauthenticated => "session has no authenticated publication proof",
            Self::Policy => "session transfer policy does not match",
            Self::Busy => "session transfer policy lock is busy",
            Self::Credentials => "session transfer credentials do not match",
            Self::Consumed => "session transfer record was already consumed",
        })
    }
}

impl std::error::Error for SessionTransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Backend(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ErrorStack> for SessionTransferError {
    fn from(error: ErrorStack) -> Self {
        Self::Backend(error)
    }
}

fn copy(bytes: &[u8], bound: usize) -> Result<Zeroizing<Vec<u8>>, SessionTransferError> {
    if bytes.len() > bound {
        return Err(SessionTransferError::TooLarge);
    }
    let mut result = Zeroizing::new(Vec::new());
    result
        .try_reserve_exact(bytes.len())
        .map_err(|_| SessionTransferError::Allocation)?;
    result.extend_from_slice(bytes);
    Ok(result)
}

fn sha256(bytes: &[u8]) -> Result<[u8; 32], SessionTransferError> {
    hash(MessageDigest::sha256(), bytes)?
        .as_ref()
        .try_into()
        .map_err(|_| SessionTransferError::Malformed)
}

fn backend() -> Result<[u8; 32], SessionTransferError> {
    let mut value = Writer::new(BACKEND.len() + 2)?;
    value.raw(BACKEND.as_bytes())?;
    value.raw(&[
        u8::from(cfg!(feature = "rpk")),
        u8::from(cfg!(feature = "fips")),
    ])?;
    sha256(&value.bytes)
}

fn key(key: &[u8; 32], label: &[u8]) -> Result<Zeroizing<[u8; 32]>, SessionTransferError> {
    let mut input = Writer::new(label.len() + 32)?;
    input.raw(label)?;
    input.raw(&backend()?)?;
    Ok(Zeroizing::new(hmac_sha256(key, &input.bytes)?))
}

/// Opaque canonical input provided by the configured credential owner.
pub struct SessionTransferCredential(Zeroizing<Vec<u8>>);

impl SessionTransferCredential {
    /// Copies a bounded, already framed HMAC input without exposing credential fields.
    pub fn from_canonical_hmac_input(input: &[u8]) -> Result<Self, SessionTransferError> {
        Ok(Self(copy(input, MAX_CREDENTIAL)?))
    }
}

/// Immutable owner policy, validated draw witness and credential custody input.
pub struct SessionTransferPolicy {
    commitment: [u8; 32],
    witness: Zeroizing<Vec<u8>>,
    credential: Option<SessionTransferCredential>,
    owner_key: Zeroizing<[u8; 32]>,
}

impl SessionTransferPolicy {
    /// Hashes complete noncredential owner policy and copies its validated witness.
    ///
    /// These bytes establish configuration identity, never peer authentication.
    pub fn new(
        policy: &[u8],
        witness: &[u8],
        credential: Option<SessionTransferCredential>,
        owner_subkey: &[u8; 32],
    ) -> Result<Self, SessionTransferError> {
        if policy.len() > MAX_POLICY {
            return Err(SessionTransferError::TooLarge);
        }
        Ok(Self {
            commitment: sha256(policy)?,
            witness: copy(witness, MAX_POLICY)?,
            credential,
            owner_key: Zeroizing::new(*owner_subkey),
        })
    }

    fn credential_tag(
        &self,
        source_key: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, SessionTransferError> {
        self.credential
            .as_ref()
            .map(|input| hmac_sha256(source_key, &input.0).map_err(SessionTransferError::Backend))
            .transpose()
    }
}

pub(super) struct ContextEpoch(Mutex<Option<Arc<AtomicBool>>>);

impl ContextEpoch {
    pub(super) fn new() -> Self {
        Self(Mutex::new(None))
    }
    pub(super) fn mutate(&self) -> MutexGuard<'_, Option<Arc<AtomicBool>>> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(epoch) = state.take() {
            epoch.store(false, Ordering::Release);
        }
        state
    }
    pub(super) fn freeze(
        &self,
    ) -> Result<MutexGuard<'_, Option<Arc<AtomicBool>>>, SessionTransferError> {
        try_policy_lock(&self.0)
    }
}

/// A context-owned mutable borrow that keeps policy freezing excluded until dropped.
pub struct SessionPolicyMutation<'a, T: ?Sized> {
    pub(super) value: &'a mut T,
    pub(super) _guard: Option<MutexGuard<'a, Option<Arc<AtomicBool>>>>,
}

impl<T: ?Sized> Deref for SessionPolicyMutation<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value
    }
}
impl<T: ?Sized> DerefMut for SessionPolicyMutation<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value
    }
}

pub(super) struct ScopeState {
    installed: Mutex<Option<Arc<InstalledPolicy>>>,
    live: AtomicBool,
    used: AtomicBool,
}
impl Default for ScopeState {
    fn default() -> Self {
        Self {
            installed: Mutex::new(None),
            live: AtomicBool::new(true),
            used: AtomicBool::new(false),
        }
    }
}

pub(super) struct InstalledPolicy {
    context: SslContext,
    epoch_owner: Arc<ContextEpoch>,
    context_epoch: Arc<AtomicBool>,
    server_name: Box<str>,
    keep_early_data: bool,
    policy: SessionTransferPolicy,
}

/// A policy installed on the actual native context, scope and configured peer.
#[derive(Clone)]
pub struct SessionPolicyBinding {
    scope: SslSessionScope,
    installed: Arc<InstalledPolicy>,
}

/// Preallocated native policy locks, borrowed from bindings retained by the owner.
///
/// Prepare this value before freezing any session stores. Acquiring its guards is
/// nonblocking, including scope locks, and never grows the prepared vectors.
pub struct PreparedSessionPolicyFreeze<'a> {
    bindings: Vec<&'a SessionPolicyBinding>,
    contexts: Vec<&'a ContextEpoch>,
    scopes: Vec<&'a ScopeState>,
    scope_guards: Vec<MutexGuard<'a, Option<Arc<InstalledPolicy>>>>,
    context_guards: Vec<MutexGuard<'a, Option<Arc<AtomicBool>>>>,
}

/// Native context and scope guards for one owner-managed store transaction.
///
/// These guards exclude context and scope changes. They do not exclude per-SSL
/// token revocation. A replacement owner must keep newly imported sessions private
/// from preparation through commit. Validation of an exposed scoped session alone
/// does not prove that its connection token cannot change before a store swap.
pub struct FrozenSessionPolicies<'a>(PreparedSessionPolicyFreeze<'a>);

fn reserved<T>(capacity: usize) -> Result<Vec<T>, SessionTransferError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| SessionTransferError::Allocation)?;
    Ok(values)
}

fn try_policy_lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, SessionTransferError> {
    match mutex.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) => Err(SessionTransferError::Busy),
        Err(TryLockError::Poisoned(_)) => Err(SessionTransferError::Policy),
    }
}

impl<'a> PreparedSessionPolicyFreeze<'a> {
    /// Reserves storage and deduplicates actual native owners before store locking.
    pub fn new(bindings: &[&'a SessionPolicyBinding]) -> Result<Self, SessionTransferError> {
        if bindings.len() > MAX_RECORDS {
            return Err(SessionTransferError::TooLarge);
        }
        let mut prepared = Self {
            bindings: reserved(bindings.len())?,
            contexts: reserved(bindings.len())?,
            scopes: reserved(bindings.len())?,
            scope_guards: reserved(bindings.len())?,
            context_guards: reserved(bindings.len())?,
        };
        for binding in bindings {
            prepared.bindings.push(*binding);
            prepared.contexts.push(&binding.installed.epoch_owner);
            prepared.scopes.push(&binding.scope.0);
        }
        // Identities are process-local and remain private. Every transaction uses
        // the same context-before-scope order, independent of cache input order.
        prepared
            .contexts
            .sort_unstable_by_key(|owner| std::ptr::from_ref(*owner) as usize);
        prepared
            .contexts
            .dedup_by(|left, right| std::ptr::eq(*left, *right));
        prepared
            .scopes
            .sort_unstable_by_key(|owner| std::ptr::from_ref(*owner) as usize);
        prepared
            .scopes
            .dedup_by(|left, right| std::ptr::eq(*left, *right));
        Ok(prepared)
    }

    /// Tries every distinct context and scope without waiting or allocating.
    ///
    /// Contention returns `Busy`; a poisoned owner returns `Policy`. Either error
    /// drops every guard acquired by this attempt without changing installed state.
    pub fn try_freeze(mut self) -> Result<FrozenSessionPolicies<'a>, SessionTransferError> {
        for owner in &self.contexts {
            self.context_guards.push(owner.freeze()?);
        }
        for owner in &self.scopes {
            self.scope_guards.push(try_policy_lock(&owner.installed)?);
        }
        Ok(FrozenSessionPolicies(self))
    }
}

impl FrozenSessionPolicies<'_> {
    /// Validates an actual prepared member, including an empty replacement's peer.
    ///
    /// This checks guarded installation identity and expiry-independent authority
    /// without locking again or allocating. Equal policy bytes on another owner
    /// never establish membership.
    pub fn validate_binding(
        &self,
        binding: &SessionPolicyBinding,
        server_name: &str,
    ) -> Result<(), SessionTransferError> {
        if !self.0.bindings.iter().any(|member| {
            Arc::ptr_eq(&member.scope.0, &binding.scope.0)
                && Arc::ptr_eq(&member.installed, &binding.installed)
        }) {
            return Err(SessionTransferError::Policy);
        }
        let context_index = self
            .0
            .contexts
            .iter()
            .position(|owner| std::ptr::eq(*owner, binding.installed.epoch_owner.as_ref()))
            .ok_or(SessionTransferError::Policy)?;
        let scope_index = self
            .0
            .scopes
            .iter()
            .position(|owner| std::ptr::eq(*owner, binding.scope.0.as_ref()))
            .ok_or(SessionTransferError::Policy)?;
        if !self.0.context_guards[context_index]
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &binding.installed.context_epoch))
            || !self.0.scope_guards[scope_index]
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &binding.installed))
        {
            return Err(SessionTransferError::Policy);
        }
        binding.validate_peer(server_name)
    }

    /// Inspects a scoped session using already-held native policy guards.
    ///
    /// This does not freeze a per-SSL token. The store owner must accept only
    /// privately prepared imports whose tokens have never been exposed to an SSL.
    pub fn validate_scoped_session(
        &self,
        binding: &SessionPolicyBinding,
        session: &ScopedSslSession,
        server_name: &str,
    ) -> Result<(), SessionTransferError> {
        self.validate_binding(binding, server_name)?;
        binding.validate_scoped_session(session, server_name)
    }
}

/// A genuine callback session retained for sealing after session-store unlock.
///
/// This value retains live native proof references. It cannot be attached, cloned
/// or converted to an attachable session, and later mutation still revokes it.
pub struct PendingSessionExport {
    session: SslSession,
    binding: SessionPolicyBinding,
    publication: Arc<SessionPublication>,
    transfer: Arc<ConnectionPolicy>,
}

impl PendingSessionExport {
    /// Rechecks proof and native expiry while sealing bounded owner metadata.
    ///
    /// Call after releasing every session-store guard. Expiry after capture fails
    /// the export rather than silently omitting this record from its owner manifest.
    pub fn seal(
        self,
        owner_metadata: &[u8],
        snapshot_key: &[u8; 32],
    ) -> Result<AuthenticatedSessionRecord, SessionTransferError> {
        self.binding.seal_session_parts(
            &self.session,
            &self.publication,
            &self.transfer,
            owner_metadata,
            snapshot_key,
        )
    }
}

impl fmt::Debug for SessionPolicyBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionPolicyBinding")
            .finish_non_exhaustive()
    }
}

impl SslSessionScope {
    /// Binds complete owner policy before first use of this scope.
    pub fn bind_transfer_policy(
        &self,
        context: &SslContextRef,
        server_name: &str,
        policy: SessionTransferPolicy,
    ) -> Result<SessionPolicyBinding, SessionTransferError> {
        use super::ScopedClientSessionMode;
        let epoch = context
            .transfer_context_epoch()
            .ok_or(SessionTransferError::Policy)?;
        let mut context_state = epoch.freeze()?;
        let keep_early_data = match context.scoped_client_session_mode() {
            ScopedClientSessionMode::Scoped => false,
            ScopedClientSessionMode::ScopedWithEarlyData => true,
            _ => return Err(SessionTransferError::Policy),
        };
        if !context.has_x509_support()
            || !context.verify_mode().contains(super::SslVerifyMode::PEER)
            || !matches!(
                context.ex_data(SslContext::cached_ex_index::<SessionVerifierProvenance>()),
                Some(SessionVerifierProvenance::Default)
            )
        {
            return Err(SessionTransferError::Policy);
        }
        if server_name.is_empty()
            || server_name.len() > 253
            || !server_name.is_ascii()
            || server_name.as_bytes().contains(&0)
        {
            return Err(SessionTransferError::Policy);
        }
        let mut installed = self
            .0
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.0.live.load(Ordering::Acquire) {
            return Err(SessionTransferError::Policy);
        }
        if let Some(current) = installed.as_ref() {
            let matches = current.context.as_ptr() == context.as_ptr()
                && super::session_hostnames_match(&current.server_name, server_name)
                && current.keep_early_data == keep_early_data
                && current.policy.commitment == policy.commitment
                && current.policy.witness.as_slice() == policy.witness.as_slice()
                && match (
                    current.policy.credential_tag(&current.policy.owner_key)?,
                    policy.credential_tag(&current.policy.owner_key)?,
                ) {
                    (None, None) => true,
                    (Some(left), Some(right)) => crate::memcmp::eq(&left, &right),
                    _ => false,
                }
                && crate::memcmp::eq(&*current.policy.owner_key, &*policy.owner_key)
                && current.context_epoch.load(Ordering::Acquire);
            if !matches {
                self.0.live.store(false, Ordering::Release);
                return Err(SessionTransferError::Policy);
            }
            return Ok(SessionPolicyBinding {
                scope: self.clone(),
                installed: Arc::clone(current),
            });
        }
        if self.0.used.load(Ordering::Acquire) {
            return Err(SessionTransferError::Policy);
        }
        let context_epoch = context_state
            .get_or_insert_with(|| Arc::new(AtomicBool::new(true)))
            .clone();
        let mut name = String::new();
        name.try_reserve_exact(server_name.len())
            .map_err(|_| SessionTransferError::Allocation)?;
        name.push_str(server_name);
        let server_name = name.into_boxed_str();
        let value = Arc::new(InstalledPolicy {
            context: context.to_owned(),
            epoch_owner: Arc::clone(&epoch),
            context_epoch,
            server_name,
            keep_early_data,
            policy,
        });
        *installed = Some(Arc::clone(&value));
        Ok(SessionPolicyBinding {
            scope: self.clone(),
            installed: value,
        })
    }

    /// Permanently retires all transfer authority installed on this scope.
    pub fn invalidate_transfer_policy(&self) {
        let _guard = self
            .0
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.0.live.store(false, Ordering::Release);
    }

    pub(super) fn transfer_use_guard(&self) -> MutexGuard<'_, Option<Arc<InstalledPolicy>>> {
        let guard = self
            .0
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.0.used.store(true, Ordering::Release);
        guard
    }
}

pub(super) struct ConnectionPolicy {
    binding: SessionPolicyBinding,
    live: AtomicBool,
}
impl ConnectionPolicy {
    pub(super) fn context_epoch_owner(&self) -> Arc<ContextEpoch> {
        Arc::clone(&self.binding.installed.epoch_owner)
    }
    pub(super) fn revoke(&self) {
        self.live.store(false, Ordering::Release);
    }
    pub(super) fn valid(&self) -> bool {
        self.live.load(Ordering::Acquire) && self.binding.valid()
    }
}

impl SessionPolicyBinding {
    pub(super) fn configuration_guard(
        &self,
    ) -> Result<MutexGuard<'_, Option<Arc<AtomicBool>>>, SessionTransferError> {
        self.installed.epoch_owner.freeze()
    }
    fn valid(&self) -> bool {
        self.scope.0.live.load(Ordering::Acquire)
            && self.installed.context_epoch.load(Ordering::Acquire)
    }
    pub(super) fn connection(
        &self,
        context: &SslContextRef,
        scope: &SslSessionScope,
        server_name: &str,
    ) -> Result<Arc<ConnectionPolicy>, SessionTransferError> {
        if !self.valid()
            || self.installed.context.as_ptr() != context.as_ptr()
            || !Arc::ptr_eq(&self.scope.0, &scope.0)
            || !super::session_hostnames_match(&self.installed.server_name, server_name)
        {
            return Err(SessionTransferError::Policy);
        }
        Ok(Arc::new(ConnectionPolicy {
            binding: self.clone(),
            live: AtomicBool::new(true),
        }))
    }

    fn validate_peer(&self, server_name: &str) -> Result<(), SessionTransferError> {
        if !self.valid()
            || !super::session_hostnames_match(&self.installed.server_name, server_name)
        {
            return Err(SessionTransferError::Policy);
        }
        Ok(())
    }

    /// Checks an authorized permit's exact recipient and expiry without consuming it.
    ///
    /// No native locks or allocations are needed. This is preparation validation;
    /// the owner must still freeze every destination policy before its atomic swap.
    pub fn validate_import_permit(
        &self,
        permit: &SessionImportPermit,
        server_name: &str,
    ) -> Result<(), SessionTransferError> {
        self.validate_peer(server_name)?;
        if !Arc::ptr_eq(&self.scope.0, &permit.recipient.scope.0)
            || !Arc::ptr_eq(&self.installed, &permit.recipient.installed)
            || self.installed.context.as_ptr() != permit.recipient.installed.context.as_ptr()
        {
            return Err(SessionTransferError::Policy);
        }
        check_session(&permit.session)?;
        Ok(())
    }

    /// Inspects exact scoped provenance and expiry without creating another record.
    ///
    /// This is not a commit proof for an exposed session: per-SSL token revocation
    /// remains possible even while context and scope policy guards are held.
    pub fn validate_scoped_session(
        &self,
        session: &ScopedSslSession,
        server_name: &str,
    ) -> Result<(), SessionTransferError> {
        self.validate_peer(server_name)?;
        if !session.matches(&self.scope, &self.installed.context, server_name) {
            return Err(SessionTransferError::Policy);
        }
        let provenance = session
            .transfer
            .as_ref()
            .ok_or(SessionTransferError::Policy)?;
        self.validate_session_proof(&session.session, &session.publication, provenance)?;
        Ok(())
    }

    /// Captures an authenticated native up-reference and its live proof without buffers.
    pub fn prepare_session_export(
        &self,
        session: &ScopedSslSession,
        server_name: &str,
    ) -> Result<PendingSessionExport, SessionTransferError> {
        self.validate_scoped_session(session, server_name)?;
        let provenance = session
            .transfer
            .as_ref()
            .ok_or(SessionTransferError::Policy)?;
        Ok(PendingSessionExport {
            session: session.session.to_owned(),
            binding: self.clone(),
            publication: Arc::clone(&session.publication),
            transfer: Arc::clone(provenance),
        })
    }

    fn validate_session_proof(
        &self,
        session: &super::SslSessionRef,
        publication: &SessionPublication,
        provenance: &ConnectionPolicy,
    ) -> Result<u64, SessionTransferError> {
        if !self.valid() {
            return Err(SessionTransferError::Policy);
        }
        if !Arc::ptr_eq(&provenance.binding.installed, &self.installed)
            || !Arc::ptr_eq(&provenance.binding.scope.0, &self.scope.0)
            || !publication.is_authenticated()
            || !provenance.valid()
        {
            return Err(SessionTransferError::Unauthenticated);
        }
        check_session(session)
    }

    /// Seals a genuine authenticated callback session and bounded owner metadata.
    pub fn seal_session(
        &self,
        session: &ScopedSslSession,
        owner_metadata: &[u8],
        snapshot_key: &[u8; 32],
    ) -> Result<AuthenticatedSessionRecord, SessionTransferError> {
        self.validate_scoped_session(session, &self.installed.server_name)?;
        let provenance = session
            .transfer
            .as_ref()
            .ok_or(SessionTransferError::Policy)?;
        self.seal_session_parts(
            &session.session,
            &session.publication,
            provenance,
            owner_metadata,
            snapshot_key,
        )
    }

    fn seal_session_parts(
        &self,
        session: &super::SslSessionRef,
        publication: &SessionPublication,
        provenance: &ConnectionPolicy,
        owner_metadata: &[u8],
        snapshot_key: &[u8; 32],
    ) -> Result<AuthenticatedSessionRecord, SessionTransferError> {
        let expires_at = self.validate_session_proof(session, publication, provenance)?;
        let native = session.bounded_transfer_bytes(MAX_SESSION)?;
        if native.len() > MAX_SESSION || owner_metadata.len() > MAX_METADATA {
            return Err(SessionTransferError::TooLarge);
        }
        let policy = &self.installed.policy;
        let credential_tag = policy.credential_tag(&policy.owner_key)?;
        let size = [
            84,
            credential_tag.map_or(0, |_| 32),
            self.installed.server_name.len(),
            policy.witness.len(),
            owner_metadata.len(),
            native.len(),
        ]
        .into_iter()
        .try_fold(0_usize, |sum, length| sum.checked_add(length))
        .ok_or(SessionTransferError::TooLarge)?;
        let mut output = Writer::new(size)?;
        output.raw(&1_u16.to_be_bytes())?;
        output.raw(&policy.commitment)?;
        output.raw(&[u8::from(credential_tag.is_some())])?;
        if let Some(tag) = credential_tag {
            output.raw(&tag)?;
        }
        output.raw(&*policy.owner_key)?;
        output.field(self.installed.server_name.as_bytes())?;
        output.raw(&[u8::from(self.installed.keep_early_data)])?;
        output.field(&policy.witness)?;
        output.field(owner_metadata)?;
        output.field(&native)?;
        let mac = hmac_sha256(
            &*key(snapshot_key, b"phantom-ticket-record-v1")?,
            &output.bytes,
        )?;
        if self
            .validate_session_proof(session, publication, provenance)
            .is_err()
        {
            // A late policy/authentication revocation must not publish a record.
            // Preserve Expired when the native ticket aged out during sealing.
            check_session(session)?;
            return Err(SessionTransferError::Policy);
        }
        Ok(AuthenticatedSessionRecord {
            body: output.bytes,
            mac,
            expires_at,
        })
    }
}

/// Opaque authenticated plaintext held only during a transfer transaction.
pub struct AuthenticatedSessionRecord {
    body: Zeroizing<Vec<u8>>,
    mac: [u8; 32],
    expires_at: u64,
}

/// Ciphertext suitable for external storage. Key holders can copy or replay it.
pub struct SessionTransferEnvelope(Zeroizing<Vec<u8>>);
impl SessionTransferEnvelope {
    /// Returns only authenticated-envelope ciphertext and public framing.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Authenticated records opened for one transaction, not client-owned staging.
pub struct VerifiedSessionEnvelope {
    records: Vec<Option<AuthenticatedSessionRecord>>,
    decoding_context: SslContext,
}

/// A decoded record bound to one recipient's installed native policy.
pub struct SessionImportPermit {
    session: SslSession,
    recipient: SessionPolicyBinding,
    metadata: Zeroizing<Vec<u8>>,
    source_witness: Zeroizing<Vec<u8>>,
}

impl SessionImportPermit {
    /// Returns the authenticated source draw witness for typed owner validation.
    ///
    /// Authentication does not establish that the owner's draw policy permits it.
    #[must_use]
    pub fn source_witness(&self) -> &[u8] {
        &self.source_witness
    }

    /// Returns authenticated owner metadata for strict protocol-owner validation.
    #[must_use]
    pub fn owner_metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Checks revocation again before creating an attachable imported session.
    pub fn into_scoped_session(self) -> Result<ScopedSslSession, SessionTransferError> {
        check_session(&self.session)?;
        let epoch = self
            .recipient
            .installed
            .context
            .transfer_context_epoch()
            .ok_or(SessionTransferError::Policy)?;
        let _context_guard = epoch.freeze()?;
        let _scope_guard = self
            .recipient
            .scope
            .0
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.recipient.valid() {
            return Err(SessionTransferError::Policy);
        }
        let publication = Arc::new(SessionPublication::new());
        publication.authenticate();
        let token = self.recipient.connection(
            &self.recipient.installed.context,
            &self.recipient.scope,
            &self.recipient.installed.server_name,
        )?;
        Ok(ScopedSslSession {
            session: self.session,
            context: self.recipient.installed.context.clone(),
            scope: self.recipient.scope.clone(),
            hostname: self.recipient.installed.server_name.clone(),
            publication,
            transfer: Some(token),
            imported: true,
        })
    }
}

fn check_session(session: &super::SslSessionRef) -> Result<u64, SessionTransferError> {
    if session.protocol_version() != SslVersion::TLS1_2
        && session.protocol_version() != SslVersion::TLS1_3
    {
        return Err(SessionTransferError::IncompatibleBackend);
    }
    let expiry = session
        .time()
        .checked_add(u64::from(session.timeout()))
        .ok_or(SessionTransferError::Expired)?;
    check_expiry(expiry)?;
    Ok(expiry)
}

fn check_expiry(expiry: u64) -> Result<(), SessionTransferError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SessionTransferError::Expired)?
        .as_secs();
    if expiry <= now {
        return Err(SessionTransferError::Expired);
    }
    Ok(())
}

/// Encrypts only records authenticated under this exact snapshot key.
pub fn seal_envelope(
    records: &[AuthenticatedSessionRecord],
    snapshot_key: &[u8; 32],
) -> Result<SessionTransferEnvelope, SessionTransferError> {
    if records.len() > MAX_RECORDS {
        return Err(SessionTransferError::TooLarge);
    }
    let record_key = key(snapshot_key, b"phantom-ticket-record-v1")?;
    let mut size = 4_usize;
    for record in records {
        if !crate::memcmp::eq(&hmac_sha256(&*record_key, &record.body)?, &record.mac) {
            return Err(SessionTransferError::Authentication);
        }
        check_expiry(record.expires_at)?;
        size = size
            .checked_add(4)
            .and_then(|n| n.checked_add(record.body.len()))
            .and_then(|n| n.checked_add(32))
            .ok_or(SessionTransferError::TooLarge)?;
    }
    let total = size
        .checked_add(HEADER + TAG)
        .filter(|n| *n <= MAX_ENVELOPE)
        .ok_or(SessionTransferError::TooLarge)?;
    let mut plaintext = Writer::new(size)?;
    plaintext.raw(
        &u32::try_from(records.len())
            .map_err(|_| SessionTransferError::TooLarge)?
            .to_be_bytes(),
    )?;
    for record in records {
        plaintext.field(&record.body)?;
        plaintext.raw(&record.mac)?;
    }
    let mut envelope = Writer::new(total)?;
    envelope.raw(MAGIC)?;
    envelope.raw(&backend()?)?;
    let mut nonce = [0; 12];
    crate::rand::rand_bytes(&mut nonce)?;
    envelope.raw(&nonce)?;
    envelope.raw(
        &u32::try_from(size)
            .map_err(|_| SessionTransferError::TooLarge)?
            .to_be_bytes(),
    )?;
    let cipher =
        ConcurrentAeadCtx::aes_256_gcm(&*key(snapshot_key, b"phantom-ticket-envelope-v1")?)?;
    let mut tag = [0; TAG];
    cipher.seal_in_place(&nonce, &mut plaintext.bytes, &mut tag, &envelope.bytes)?;
    envelope.raw(&plaintext.bytes)?;
    envelope.raw(&tag)?;
    for record in records {
        check_expiry(record.expires_at)?;
    }
    Ok(SessionTransferEnvelope(envelope.bytes))
}

/// Authenticates before parsing records, then strict-decodes every native session.
///
/// The decoding context grants parser compatibility, never recipient authority.
pub fn open_envelope(
    snapshot: &[u8],
    snapshot_key: &[u8; 32],
    decoding_context: &SslContextRef,
) -> Result<VerifiedSessionEnvelope, SessionTransferError> {
    if snapshot.len() > MAX_ENVELOPE {
        return Err(SessionTransferError::TooLarge);
    }
    if snapshot.len() < HEADER + TAG || &snapshot[..8] != MAGIC {
        return Err(SessionTransferError::Malformed);
    }
    if snapshot[8..40] != backend()? {
        return Err(SessionTransferError::IncompatibleBackend);
    }
    let length = u32::from_be_bytes(
        snapshot[52..56]
            .try_into()
            .map_err(|_| SessionTransferError::Malformed)?,
    ) as usize;
    if length != snapshot.len() - HEADER - TAG {
        return Err(SessionTransferError::Malformed);
    }
    if !decoding_context.has_x509_support() {
        return Err(SessionTransferError::IncompatibleBackend);
    }
    let mut plaintext = copy(&snapshot[HEADER..HEADER + length], MAX_ENVELOPE)?;
    let cipher =
        ConcurrentAeadCtx::aes_256_gcm(&*key(snapshot_key, b"phantom-ticket-envelope-v1")?)?;
    cipher
        .open_in_place(
            &snapshot[40..52],
            &mut plaintext,
            &snapshot[HEADER + length..],
            &snapshot[..HEADER],
        )
        .map_err(|_| SessionTransferError::Authentication)?;
    let mut reader = Reader(&plaintext);
    let count = reader.number()? as usize;
    if count > MAX_RECORDS {
        return Err(SessionTransferError::TooLarge);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| SessionTransferError::Allocation)?;
    let record_key = key(snapshot_key, b"phantom-ticket-record-v1")?;
    for _ in 0..count {
        let body = reader.field(MAX_POLICY + MAX_METADATA + MAX_SESSION + 512)?;
        let mac: [u8; 32] = reader
            .take(32)?
            .try_into()
            .map_err(|_| SessionTransferError::Malformed)?;
        if !crate::memcmp::eq(&hmac_sha256(&*record_key, body)?, &mac) {
            return Err(SessionTransferError::Authentication);
        }
        let parsed = Record::parse(body)?;
        let decoded = SslSession::from_bytes(parsed.native, decoding_context)?;
        let expires_at = check_session(&decoded)?;
        records.push(Some(AuthenticatedSessionRecord {
            body: copy(body, MAX_ENVELOPE)?,
            mac,
            expires_at,
        }));
    }
    if !reader.0.is_empty() {
        return Err(SessionTransferError::Malformed);
    }
    Ok(VerifiedSessionEnvelope {
        records,
        decoding_context: decoding_context.to_owned(),
    })
}

impl VerifiedSessionEnvelope {
    /// Copies only remaining authenticated records into a compact new transaction.
    ///
    /// All records are strict-decoded and checked for expiry before any body is
    /// copied. Failure leaves this transaction untouched and grants no authority.
    pub fn try_clone_remaining(&self) -> Result<Self, SessionTransferError> {
        let mut count = 0_usize;
        let mut total = 4_usize;
        for record in self.records.iter().flatten() {
            let parsed = Record::parse(&record.body)?;
            let decoded = SslSession::from_bytes(parsed.native, &self.decoding_context)?;
            check_session(&decoded)?;
            count += 1;
            total = total
                .checked_add(36)
                .and_then(|size| size.checked_add(record.body.len()))
                .filter(|size| *size <= MAX_ENVELOPE - HEADER - TAG)
                .ok_or(SessionTransferError::TooLarge)?;
        }
        if count > MAX_RECORDS {
            return Err(SessionTransferError::TooLarge);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| SessionTransferError::Allocation)?;
        for record in self.records.iter().flatten() {
            records.push(Some(AuthenticatedSessionRecord {
                body: copy(&record.body, MAX_ENVELOPE)?,
                mac: record.mac,
                expires_at: record.expires_at,
            }));
        }
        Ok(Self {
            records,
            decoding_context: self.decoding_context.clone(),
        })
    }

    /// Rekeys only remaining authenticated records without changing this transaction.
    ///
    /// Original source commitments, credential custody subkeys and provenance
    /// remain inside the encrypted records. No recipient permit is issued.
    pub fn seal_remaining_envelope(
        &self,
        new_key: &[u8; 32],
    ) -> Result<SessionTransferEnvelope, SessionTransferError> {
        let cloned = self.try_clone_remaining()?;
        let record_key = key(new_key, b"phantom-ticket-record-v1")?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(cloned.records.len())
            .map_err(|_| SessionTransferError::Allocation)?;
        for mut record in cloned.records.into_iter().flatten() {
            record.mac = hmac_sha256(&*record_key, &record.body)?;
            records.push(record);
        }
        seal_envelope(&records, new_key)
    }
    /// Returns the number of original slots, including consumed slots.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Returns the authenticated source draw witness for typed owner validation.
    ///
    /// Consumed or invalid slots fail. This grants neither native authority nor
    /// evidence that the witness is an allowed draw under the owner's policy.
    pub fn source_witness(&self, index: usize) -> Result<&[u8], SessionTransferError> {
        let record = self
            .records
            .get(index)
            .ok_or(SessionTransferError::Malformed)?
            .as_ref()
            .ok_or(SessionTransferError::Consumed)?;
        Ok(Record::parse(&record.body)?.source_witness)
    }

    /// Returns authenticated application metadata, never native bytes or custody keys.
    pub fn owner_metadata(&self, index: usize) -> Result<&[u8], SessionTransferError> {
        let record = self
            .records
            .get(index)
            .ok_or(SessionTransferError::Malformed)?
            .as_ref()
            .ok_or(SessionTransferError::Consumed)?;
        Ok(Record::parse(&record.body)?.metadata)
    }
    /// Recomputes actual recipient credentials under the authenticated source subkey.
    ///
    /// Success consumes only this transaction-local record. Existing client staging
    /// must remain unchanged until the owner commits all prepared replacements.
    pub fn authorize_record(
        &mut self,
        index: usize,
        recipient: &SessionPolicyBinding,
    ) -> Result<SessionImportPermit, SessionTransferError> {
        let record = self
            .records
            .get(index)
            .ok_or(SessionTransferError::Malformed)?
            .as_ref()
            .ok_or(SessionTransferError::Consumed)?;
        let parsed = Record::parse(&record.body)?;
        if !recipient.valid()
            || !crate::memcmp::eq(parsed.commitment, &recipient.installed.policy.commitment)
            || !super::session_hostnames_match(parsed.hostname, &recipient.installed.server_name)
            || parsed.keep_early_data != recipient.installed.keep_early_data
        {
            return Err(SessionTransferError::Policy);
        }
        let source_key: &[u8; 32] = parsed
            .source_key
            .try_into()
            .map_err(|_| SessionTransferError::Malformed)?;
        let tag = recipient.installed.policy.credential_tag(source_key)?;
        match (tag, parsed.credential_tag) {
            (None, None) => {}
            (Some(actual), Some(expected)) if crate::memcmp::eq(&actual, expected) => {}
            _ => return Err(SessionTransferError::Credentials),
        }
        let session = SslSession::from_bytes(parsed.native, &recipient.installed.context)?;
        check_session(&session)?;
        let session = if recipient.installed.keep_early_data {
            session
        } else {
            session.copy_without_early_data()?
        };
        let metadata = copy(parsed.metadata, MAX_METADATA)?;
        let source_witness = copy(parsed.source_witness, MAX_POLICY)?;
        if !recipient.valid() {
            return Err(SessionTransferError::Policy);
        }
        self.records[index] = None;
        Ok(SessionImportPermit {
            session,
            recipient: recipient.clone(),
            metadata,
            source_witness,
        })
    }
}

struct Record<'a> {
    commitment: &'a [u8],
    credential_tag: Option<&'a [u8]>,
    source_key: &'a [u8],
    hostname: &'a str,
    keep_early_data: bool,
    metadata: &'a [u8],
    source_witness: &'a [u8],
    native: &'a [u8],
}
impl<'a> Record<'a> {
    fn parse(body: &'a [u8]) -> Result<Self, SessionTransferError> {
        let mut r = Reader(body);
        if r.take(2)? != 1_u16.to_be_bytes() {
            return Err(SessionTransferError::Malformed);
        }
        let commitment = r.take(32)?;
        let credential_tag = if r.boolean()? {
            Some(r.take(32)?)
        } else {
            None
        };
        let source_key = r.take(32)?;
        let hostname =
            std::str::from_utf8(r.field(253)?).map_err(|_| SessionTransferError::Malformed)?;
        if hostname.is_empty() || !hostname.is_ascii() || hostname.as_bytes().contains(&0) {
            return Err(SessionTransferError::Malformed);
        }
        let keep_early_data = r.boolean()?;
        let source_witness = r.field(MAX_POLICY)?;
        let metadata = r.field(MAX_METADATA)?;
        let native = r.field(MAX_SESSION)?;
        if !r.0.is_empty() {
            return Err(SessionTransferError::Malformed);
        }
        Ok(Self {
            commitment,
            credential_tag,
            source_key,
            hostname,
            keep_early_data,
            metadata,
            source_witness,
            native,
        })
    }
}

struct Writer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Writer {
    fn new(size: usize) -> Result<Self, SessionTransferError> {
        if size > MAX_ENVELOPE {
            return Err(SessionTransferError::TooLarge);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(size)
            .map_err(|_| SessionTransferError::Allocation)?;
        Ok(Self { bytes, limit: size })
    }
    fn raw(&mut self, value: &[u8]) -> Result<(), SessionTransferError> {
        if self
            .bytes
            .len()
            .checked_add(value.len())
            .filter(|size| *size <= self.limit)
            .is_none()
        {
            return Err(SessionTransferError::TooLarge);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    fn field(&mut self, value: &[u8]) -> Result<(), SessionTransferError> {
        self.raw(
            &u32::try_from(value.len())
                .map_err(|_| SessionTransferError::TooLarge)?
                .to_be_bytes(),
        )?;
        self.raw(value)?;
        Ok(())
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], SessionTransferError> {
        if size > self.0.len() {
            return Err(SessionTransferError::Malformed);
        }
        let (head, tail) = self.0.split_at(size);
        self.0 = tail;
        Ok(head)
    }
    fn number(&mut self) -> Result<u32, SessionTransferError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| SessionTransferError::Malformed)?,
        ))
    }
    fn field(&mut self, bound: usize) -> Result<&'a [u8], SessionTransferError> {
        let size = self.number()? as usize;
        if size > bound {
            return Err(SessionTransferError::TooLarge);
        }
        self.take(size)
    }
    fn boolean(&mut self) -> Result<bool, SessionTransferError> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SessionTransferError::Malformed),
        }
    }
}

#[cfg(test)]
mod tests;

macro_rules! redacted_debug {
    ($($kind:ty),+ $(,)?) => { $(impl fmt::Debug for $kind {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct(stringify!($kind)).finish_non_exhaustive()
        }
    })+ };
}
redacted_debug!(
    SessionTransferCredential,
    SessionTransferPolicy,
    AuthenticatedSessionRecord,
    SessionTransferEnvelope,
    VerifiedSessionEnvelope,
    SessionImportPermit,
    PreparedSessionPolicyFreeze<'_>,
    FrozenSessionPolicies<'_>,
    PendingSessionExport
);
