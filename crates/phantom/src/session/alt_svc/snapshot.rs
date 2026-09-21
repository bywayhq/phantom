//! Caller-owned persistence of learned Alt-Svc alternatives.

use std::{
    collections::HashSet,
    fmt,
    net::Ipv6Addr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tracing::debug;

use super::{
    AltSvcLocation, AltSvcStore, Entry, MAX_DELTA_SECONDS, OriginKey, canonical_origin,
    expiration_at,
};
use crate::authority::Endpoint;

/// Alt-Svc alternatives exported from one client, least recently used first.
///
/// A snapshot contains only each origin's canonical ASCII serialization, the
/// alternative's QUIC host and port, and an absolute expiry rounded down to a
/// whole second. It holds no connection, TLS ticket, route, cookie, or
/// credential state. The client store is keyed by origin for direct routes, so
/// a snapshot describes alternatives for the direct route only.
///
/// Phantom does not serialize snapshots; callers persist the accessor values
/// in a format of their choice and rebuild entries with
/// [`AltSvcSnapshotEntry::new`]. Formatting with `Debug` omits hosts.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct AltSvcSnapshot {
    entries: Vec<AltSvcSnapshotEntry>,
}

impl AltSvcSnapshot {
    /// Creates a snapshot from entries ordered least recently used first.
    ///
    /// Entries are validated when imported, not here.
    #[must_use]
    pub fn new(entries: Vec<AltSvcSnapshotEntry>) -> Self {
        Self { entries }
    }

    /// Returns the entries, least recently used first.
    #[must_use]
    pub fn entries(&self) -> &[AltSvcSnapshotEntry] {
        &self.entries
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the snapshot has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Debug for AltSvcSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AltSvcSnapshot")
            .field("entries", &self.entries)
            .finish()
    }
}

/// One origin's HTTP/3 alternative in an [`AltSvcSnapshot`].
#[derive(Clone, Eq, PartialEq)]
pub struct AltSvcSnapshotEntry {
    origin: Box<str>,
    alternative_host: Box<str>,
    alternative_port: u16,
    expires_at: SystemTime,
}

impl AltSvcSnapshotEntry {
    /// Creates an entry for later import.
    ///
    /// `origin` must be a canonical HTTPS origin serialization, such as
    /// `https://example.com` or `https://example.com:8443`. The alternative
    /// host is canonical and unbracketed, such as `alt.example.com`,
    /// `192.0.2.1`, or `2001:db8::1`. Import revalidates every part.
    #[must_use]
    pub fn new(
        origin: impl Into<Box<str>>,
        alternative_host: impl Into<Box<str>>,
        alternative_port: u16,
        expires_at: SystemTime,
    ) -> Self {
        Self {
            origin: origin.into(),
            alternative_host: alternative_host.into(),
            alternative_port,
            expires_at,
        }
    }

    /// Returns the canonical ASCII serialization of the HTTPS origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Returns the canonical, unbracketed host that receives QUIC packets.
    #[must_use]
    pub fn alternative_host(&self) -> &str {
        &self.alternative_host
    }

    /// Returns the UDP port that receives QUIC packets.
    #[must_use]
    pub const fn alternative_port(&self) -> u16 {
        self.alternative_port
    }

    /// Returns the absolute wall-clock time after which the entry is unusable.
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

impl fmt::Debug for AltSvcSnapshotEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AltSvcSnapshotEntry")
            .field("alternative_port", &self.alternative_port)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Why [`Client::import_alt_svc`](crate::Client::import_alt_svc) rejected a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AltSvcSnapshotErrorKind {
    /// The client was built without Alt-Svc.
    Disabled,
    /// An entry's origin is not a canonical HTTPS origin serialization.
    NoncanonicalOrigin,
    /// An entry's alternative host or port is not a canonical QUIC location.
    InvalidAlternative,
}

/// A rejected Alt-Svc snapshot import; the client state is unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AltSvcSnapshotError {
    kind: AltSvcSnapshotErrorKind,
    entry: Option<usize>,
}

impl AltSvcSnapshotError {
    pub(crate) const fn disabled() -> Self {
        Self {
            kind: AltSvcSnapshotErrorKind::Disabled,
            entry: None,
        }
    }

    const fn entry(kind: AltSvcSnapshotErrorKind, index: usize) -> Self {
        Self {
            kind,
            entry: Some(index),
        }
    }

    /// Returns the rejection category.
    #[must_use]
    pub const fn kind(&self) -> AltSvcSnapshotErrorKind {
        self.kind
    }

    /// Returns the index of the rejected entry, if one entry caused the error.
    #[must_use]
    pub const fn entry_index(&self) -> Option<usize> {
        self.entry
    }
}

impl fmt::Display for AltSvcSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            AltSvcSnapshotErrorKind::Disabled => "Alt-Svc is not enabled for this client",
            AltSvcSnapshotErrorKind::NoncanonicalOrigin => {
                "Alt-Svc snapshot origin is not a canonical HTTPS origin"
            }
            AltSvcSnapshotErrorKind::InvalidAlternative => {
                "Alt-Svc snapshot alternative is not a canonical host and nonzero port"
            }
        };
        match self.entry {
            Some(index) => write!(formatter, "{message} (entry {index})"),
            None => formatter.write_str(message),
        }
    }
}

impl std::error::Error for AltSvcSnapshotError {}

impl AltSvcStore {
    pub(crate) fn export(&self) -> AltSvcSnapshot {
        // Read the wall clock before the monotonic clock so the exported
        // expiry can only be earlier than the stored one.
        let system_now = SystemTime::now();
        let now = Instant::now();
        let entries = self.lock_entries();
        AltSvcSnapshot::new(
            entries
                .iter()
                .filter_map(|entry| {
                    let remaining = entry.expires_at.checked_duration_since(now)?;
                    let expires_at = floor_to_second(system_now.checked_add(remaining)?);
                    (expires_at > system_now).then(|| AltSvcSnapshotEntry {
                        origin: entry.origin.serialize().into(),
                        alternative_host: entry.location.host.clone(),
                        alternative_port: entry.location.port,
                        expires_at,
                    })
                })
                .collect(),
        )
    }

    /// Validates every entry, then adds unexpired entries for origins this
    /// store does not already hold, ranked older than every held entry.
    pub(crate) fn import(&self, snapshot: &AltSvcSnapshot) -> Result<(), AltSvcSnapshotError> {
        let mut validated = Vec::with_capacity(snapshot.len());
        for (index, entry) in snapshot.entries().iter().enumerate() {
            let origin = parse_origin(&entry.origin).ok_or(AltSvcSnapshotError::entry(
                AltSvcSnapshotErrorKind::NoncanonicalOrigin,
                index,
            ))?;
            let location =
                parse_alternative(&entry.alternative_host, entry.alternative_port).ok_or(
                    AltSvcSnapshotError::entry(AltSvcSnapshotErrorKind::InvalidAlternative, index),
                )?;
            validated.push((origin, location, entry.expires_at));
        }

        // Read the monotonic clock before the wall clock so the imported
        // lifetime can only be shorter than the snapshot's.
        let now = Instant::now();
        let system_now = SystemTime::now();
        let mut entries = self.lock_entries();
        let mut seen = HashSet::new();
        // Newest first: a later duplicate wins and capacity keeps the newest.
        for (origin, location, expires_at) in validated.into_iter().rev() {
            if !seen.insert(origin.clone()) {
                continue;
            }
            let Ok(remaining) = expires_at.duration_since(system_now) else {
                continue;
            };
            let remaining = remaining.min(Duration::from_secs(MAX_DELTA_SECONDS));
            if remaining.is_zero()
                || entries.len() == self.capacity.get()
                || entries.iter().any(|held| held.origin == origin)
            {
                continue;
            }
            entries.push_front(Entry {
                origin,
                location,
                expires_at: expiration_at_duration(now, remaining),
                generation: self
                    .next_generation
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            });
        }
        debug!(outcome = "imported", "imported Alt-Svc client state");
        Ok(())
    }
}

fn parse_origin(value: &str) -> Option<OriginKey> {
    let url = url::Url::parse(value).ok()?;
    if url.scheme() != "https" || url.origin().ascii_serialization() != value {
        return None;
    }
    let authority = format!("{}:{}", url.host_str()?, url.port_or_known_default()?);
    let endpoint = Endpoint::new(authority.parse().ok()?, 443).ok()?;
    (canonical_origin(&endpoint) == value).then(|| OriginKey::new(&endpoint))
}

fn parse_alternative(host: &str, port: u16) -> Option<AltSvcLocation> {
    if port == 0 || host.is_empty() {
        return None;
    }
    let canonical = if host.contains(':') {
        host.parse::<Ipv6Addr>().ok()?.to_string()
    } else {
        url::Host::parse(host).ok()?.to_string()
    };
    (canonical == host).then(|| AltSvcLocation {
        host: host.into(),
        port,
    })
}

fn floor_to_second(time: SystemTime) -> SystemTime {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since_epoch) => UNIX_EPOCH + Duration::from_secs(since_epoch.as_secs()),
        Err(_) => time,
    }
}

fn expiration_at_duration(now: Instant, remaining: Duration) -> Instant {
    now.checked_add(remaining)
        .unwrap_or_else(|| expiration_at(now, remaining.as_secs()))
}
