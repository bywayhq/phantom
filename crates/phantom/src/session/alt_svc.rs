use std::{
    collections::VecDeque,
    net::Ipv6Addr,
    num::NonZeroUsize,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use phantom_net::{
    OrderedResponseHeaders,
    http2::{AltSvcFrameScope, AltSvcFrames},
    http3::{Http3ConnectorError, Http3ConnectorErrorKind},
};
use tracing::debug;

use crate::{RequestError, RequestErrorKind, Route, TimeoutPhase, authority::Endpoint};

const DEFAULT_MAX_AGE: u64 = 24 * 60 * 60;
const MAX_DELTA_SECONDS: u64 = 1 << 31;

pub(super) struct AltSvcSelection {
    location: AltSvcLocation,
    generation: u64,
    broken: bool,
    origin_quic_recently_broken: bool,
}

impl AltSvcSelection {
    #[cfg(test)]
    const fn is_broken(&self) -> bool {
        self.broken
    }

    #[cfg(test)]
    fn host(&self) -> &str {
        self.location.host()
    }

    #[cfg(test)]
    const fn port(&self) -> u16 {
        self.location.port()
    }
}

/// An HTTP/3 alternative selected for one negotiated request.
#[derive(Clone, Debug)]
pub(crate) struct AlternativeTarget {
    location: AltSvcLocation,
    source: AlternativeSource,
    broken: bool,
    origin_quic_recently_broken: bool,
}

/// Where an alternative came from.
#[derive(Clone, Debug)]
enum AlternativeSource {
    /// A stored Alt-Svc advertisement, named on the wire by `Alt-Used`.
    AltSvc { alt_used: Box<str>, generation: u64 },
    /// An HTTPS DNS record for the origin's own location.
    #[cfg(feature = "https-records")]
    HttpsRecord,
}

impl AlternativeTarget {
    pub(super) fn new(selection: &AltSvcSelection) -> Self {
        Self {
            location: selection.location.clone(),
            source: AlternativeSource::AltSvc {
                alt_used: selection.location.authority(),
                generation: selection.generation,
            },
            broken: selection.broken,
            origin_quic_recently_broken: selection.origin_quic_recently_broken,
        }
    }

    /// Returns the origin's own location, as an HTTPS record advertising
    /// `h3` names it.
    #[cfg(feature = "https-records")]
    pub(super) fn https_record(
        origin: &Endpoint,
        broken: bool,
        origin_quic_recently_broken: bool,
    ) -> Self {
        Self {
            location: AltSvcLocation::origin(origin),
            source: AlternativeSource::HttpsRecord,
            broken,
            origin_quic_recently_broken,
        }
    }

    pub(crate) fn host(&self) -> &str {
        self.location.host()
    }

    pub(crate) const fn port(&self) -> u16 {
        self.location.port()
    }

    /// Returns the canonical `Alt-Used` authority with an explicit port, for
    /// an Alt-Svc alternative only.
    ///
    /// An HTTPS record leads to the origin's own location, which RFC 7838
    /// does not call an alternative service, so no `Alt-Used` is sent.
    pub(crate) fn alt_used(&self) -> Option<&str> {
        match &self.source {
            AlternativeSource::AltSvc { alt_used, .. } => Some(alt_used),
            #[cfg(feature = "https-records")]
            AlternativeSource::HttpsRecord => None,
        }
    }

    /// Returns the store generation of an Alt-Svc alternative.
    pub(super) const fn generation(&self) -> Option<u64> {
        match &self.source {
            AlternativeSource::AltSvc { generation, .. } => Some(*generation),
            #[cfg(feature = "https-records")]
            AlternativeSource::HttpsRecord => None,
        }
    }

    pub(crate) const fn is_broken(&self) -> bool {
        self.broken
    }

    /// Returns this alternative with early data disallowed, after QUIC to
    /// the origin failed a handshake that had sent early data.
    pub(crate) fn without_early_data(mut self) -> Self {
        self.origin_quic_recently_broken = true;
        self
    }

    /// Returns whether a raced setup to this alternative may offer early
    /// (0-RTT) data.
    ///
    /// Chromium's QUIC attempt requires handshake confirmation, and so sends
    /// no early data, when QUIC to the origin's own host and port was
    /// recently broken: in a broken period, or failed and not confirmed
    /// since (`QuicSessionAttempt::DoCreateSession`,
    /// `net/quic/quic_session_attempt.cc` lines 83-84 and 227-228,
    /// `QuicSessionPool::WasQuicRecentlyBroken`,
    /// `net/quic/quic_session_pool.cc` lines 2553-2560, and
    /// `BrokenAlternativeServices::WasRecentlyBroken`,
    /// `net/http/broken_alternative_services.cc` lines 198-206, at
    /// 154.0.8037.58). Otherwise the attempt completes once 0-RTT keys are
    /// set, and a replay-safe request goes out as early data.
    pub(crate) const fn allows_early_data(&self) -> bool {
        !self.origin_quic_recently_broken
    }

    pub(super) const fn location(&self) -> &AltSvcLocation {
        &self.location
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AltSvcLocation {
    host: Box<str>,
    port: u16,
}

impl AltSvcLocation {
    fn origin(origin: &Endpoint) -> Self {
        Self {
            host: origin.host().to_ascii_lowercase().into(),
            port: origin.port(),
        }
    }

    pub(super) fn host(&self) -> &str {
        &self.host
    }

    pub(super) const fn port(&self) -> u16 {
        self.port
    }

    pub(super) fn authority(&self) -> Box<str> {
        if self.host.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port).into()
        } else {
            format!("{}:{}", self.host, self.port).into()
        }
    }
}

pub(super) struct AltSvcStore {
    capacity: NonZeroUsize,
    entries: Mutex<VecDeque<Entry>>,
    /// Race failure history by origin and alternative, least recently marked
    /// first. A record outlives its broken period so a later failure backs off
    /// further; a successful alternative connection removes it.
    broken: Mutex<VecDeque<BrokenRecord>>,
    next_generation: AtomicU64,
}

impl AltSvcStore {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::new()),
            broken: Mutex::new(VecDeque::new()),
            next_generation: AtomicU64::new(1),
        }
    }

    pub(super) const fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    pub(super) fn learn(&self, origin: &Endpoint, route: &Route, headers: &OrderedResponseHeaders) {
        self.learn_fields_at(
            origin,
            route,
            headers.iter().map(|field| (field.name(), field.value())),
            Instant::now(),
        );
    }

    /// Applies HTTP/2 ALTSVC frames in arrival order.
    ///
    /// A stream-0 frame applies only when its origin is byte-identical to the
    /// request's canonical ASCII origin serialization; a request-stream frame
    /// applies to the request origin (RFC 7838 section 4).
    pub(super) fn learn_frames(&self, origin: &Endpoint, route: &Route, frames: &AltSvcFrames) {
        self.learn_frames_at(
            origin,
            route,
            frames.as_slice().iter().map(|frame| {
                let scope = match frame.scope() {
                    AltSvcFrameScope::Connection(origin) => Some(origin.as_ref()),
                    AltSvcFrameScope::Stream => None,
                };
                (scope, frame.field_value())
            }),
            Instant::now(),
        );
    }

    fn learn_frames_at<'a>(
        &self,
        origin: &Endpoint,
        route: &Route,
        frames: impl IntoIterator<Item = (Option<&'a [u8]>, &'a [u8])>,
        now: Instant,
    ) {
        let canonical = canonical_origin(origin);
        for (frame_origin, value) in frames {
            if frame_origin.is_some_and(|frame_origin| frame_origin != canonical.as_bytes()) {
                debug!(outcome = "other_origin", "ignored Alt-Svc frame");
                continue;
            }
            self.learn_fields_at(origin, route, [("alt-svc", value)], now);
        }
    }

    pub(super) fn get(&self, origin: &Endpoint, route: &Route) -> Option<AltSvcSelection> {
        self.get_at(origin, route, Instant::now())
    }

    #[cfg(test)]
    fn remove(&self, origin: &Endpoint, route: &Route) {
        self.remove_key(&StoreKey::new(origin, route));
    }

    pub(super) fn remove_if_current(&self, origin: &Endpoint, route: &Route, generation: u64) {
        let key = StoreKey::new(origin, route);
        let mut entries = self.lock_entries();
        if let Some(position) = entries
            .iter()
            .position(|entry| entry.key == key && entry.generation == generation)
        {
            entries.remove(position);
            debug!(
                outcome = "cleared",
                "removed attempted Alt-Svc client state"
            );
        }
    }

    pub(super) fn clear(&self) {
        self.lock_entries().clear();
        self.lock_broken().clear();
    }

    /// Marks `location` broken for `origin` after it failed a race the origin won.
    pub(super) fn mark_broken(
        &self,
        origin: &Endpoint,
        route: &Route,
        location: &AltSvcLocation,
        backoff: AltSvcBrokenBackoff,
    ) {
        self.mark_broken_at(origin, route, location, backoff, Instant::now());
    }

    fn mark_broken_at(
        &self,
        origin: &Endpoint,
        route: &Route,
        location: &AltSvcLocation,
        backoff: AltSvcBrokenBackoff,
        now: Instant,
    ) {
        let key = StoreKey::new(origin, route);
        let mut broken = self.lock_broken();
        let mut record = match broken
            .iter()
            .position(|record| record.key == key && &record.location == location)
            .and_then(|position| broken.remove(position))
        {
            Some(record) => record,
            None => {
                if broken.len() == self.capacity.get() {
                    broken.pop_front();
                }
                BrokenRecord {
                    key,
                    location: location.clone(),
                    failures: 0,
                    until: now,
                }
            }
        };
        // Like Chromium, every failure counts toward the next period, but a
        // failure inside an active broken period does not extend it
        // (`BrokenAlternativeServices::MarkBrokenImpl`,
        // `net/http/broken_alternative_services.cc` lines 137-154 at
        // 153.0.8010.48).
        if record.until > now {
            record.failures = record.failures.saturating_add(1);
            debug!(
                outcome = "already_broken",
                failures = record.failures,
                "counted a failure of a broken Alt-Svc alternative"
            );
            broken.push_back(record);
            return;
        }
        let period = backoff.period(record.failures);
        record.until = now
            .checked_add(period)
            .unwrap_or_else(|| expiration_at(now, MAX_DELTA_SECONDS));
        record.failures = record.failures.saturating_add(1);
        debug!(
            outcome = "broken",
            failures = record.failures,
            broken_ms = u64::try_from(period.as_millis()).unwrap_or(u64::MAX),
            "marked Alt-Svc alternative broken"
        );
        broken.push_back(record);
    }

    /// Records that QUIC to `origin`'s own host and port failed its handshake
    /// after a connection there was already in use, without a broken period.
    ///
    /// Chromium marks QUIC to the session's server recently broken when a
    /// session that carried a request closes before its handshake completes
    /// (`QuicSessionPool::ProcessGoingAwaySession`,
    /// `net/quic/quic_session_pool.cc` lines 2714-2731 at 154.0.8037.58):
    /// the alternative is still raced, but its attempts send no early data
    /// until QUIC to the origin connects again.
    pub(super) fn mark_origin_quic_recently_broken(&self, origin: &Endpoint, route: &Route) {
        let key = StoreKey::new(origin, route);
        let location = AltSvcLocation::origin(origin);
        let mut broken = self.lock_broken();
        if broken
            .iter()
            .any(|record| record.key == key && record.location == location)
        {
            return;
        }
        if broken.len() == self.capacity.get() {
            broken.pop_front();
        }
        broken.push_back(BrokenRecord {
            key,
            location,
            failures: 0,
            until: Instant::now(),
        });
        debug!(
            outcome = "recently_broken",
            "marked QUIC to the origin recently broken"
        );
    }

    /// Clears the failure history of `location` after it connected.
    pub(super) fn confirm(&self, origin: &Endpoint, route: &Route, location: &AltSvcLocation) {
        let key = StoreKey::new(origin, route);
        let mut broken = self.lock_broken();
        if let Some(position) = broken
            .iter()
            .position(|record| record.key == key && &record.location == location)
        {
            broken.remove(position);
            debug!(outcome = "confirmed", "cleared Alt-Svc broken state");
        }
        // A completed QUIC handshake for the origin also confirms QUIC to the
        // origin's own host and port, as Chromium keys it, unless that
        // location is in a broken period of its own.
        let own = AltSvcLocation::origin(origin);
        let now = Instant::now();
        if let Some(position) = broken
            .iter()
            .position(|record| record.key == key && record.location == own && record.until <= now)
        {
            broken.remove(position);
        }
    }

    /// Returns whether `location` is in a broken period for `origin` and `route`.
    #[cfg(feature = "https-records")]
    pub(super) fn is_broken(
        &self,
        origin: &Endpoint,
        route: &Route,
        location: &AltSvcLocation,
    ) -> bool {
        self.is_broken_at(&StoreKey::new(origin, route), location, Instant::now())
    }

    /// Returns whether QUIC to `origin`'s own host and port failed a race
    /// and has not connected since, whether or not its broken period ended.
    #[cfg(feature = "https-records")]
    pub(super) fn origin_quic_recently_broken(&self, origin: &Endpoint, route: &Route) -> bool {
        self.has_failed(
            &StoreKey::new(origin, route),
            &AltSvcLocation::origin(origin),
        )
    }

    /// Returns whether `location` has a failure record, which outlives its
    /// broken period until the location connects again.
    fn has_failed(&self, key: &StoreKey, location: &AltSvcLocation) -> bool {
        self.lock_broken()
            .iter()
            .any(|record| &record.key == key && &record.location == location)
    }

    fn is_broken_at(&self, key: &StoreKey, location: &AltSvcLocation, now: Instant) -> bool {
        self.lock_broken()
            .iter()
            .any(|record| &record.key == key && &record.location == location && record.until > now)
    }

    fn lock_broken(&self) -> MutexGuard<'_, VecDeque<BrokenRecord>> {
        match self.broken.lock() {
            Ok(broken) => broken,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn learn_fields_at<'a>(
        &self,
        origin: &Endpoint,
        route: &Route,
        fields: impl IntoIterator<Item = (&'a str, &'a [u8])>,
        now: Instant,
    ) {
        let update = match parse_response_fields(origin, fields) {
            Ok(Some(update)) => update,
            Ok(None) => return,
            Err(()) => {
                debug!(outcome = "malformed", "ignored Alt-Svc response field");
                return;
            }
        };
        let key = StoreKey::new(origin, route);
        match update {
            Update::Clear => self.remove_key(&key),
            Update::Replace(None) => self.remove_key(&key),
            Update::Replace(Some(alternative)) => {
                let remaining = alternative.max_age.saturating_sub(alternative.age);
                if remaining == 0 {
                    self.remove_key(&key);
                    return;
                }
                let expires_at = expiration_at(now, remaining);
                self.replace(Entry {
                    key,
                    location: alternative.location,
                    expires_at,
                    generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
                });
            }
        }
    }

    fn get_at(&self, origin: &Endpoint, route: &Route, now: Instant) -> Option<AltSvcSelection> {
        let key = StoreKey::new(origin, route);
        let mut entries = self.lock_entries();
        let position = entries.iter().position(|entry| entry.key == key)?;
        let entry = entries.remove(position)?;
        if entry.expires_at <= now {
            debug!(outcome = "expired", "removed expired Alt-Svc origin");
            return None;
        }
        let broken = self.is_broken_at(&key, &entry.location, now);
        let origin_quic_recently_broken = self.has_failed(&key, &AltSvcLocation::origin(origin));
        let selection = AltSvcSelection {
            location: entry.location.clone(),
            generation: entry.generation,
            broken,
            origin_quic_recently_broken,
        };
        entries.push_back(entry);
        Some(selection)
    }

    fn replace(&self, entry: Entry) {
        let mut entries = self.lock_entries();
        if let Some(position) = entries
            .iter()
            .position(|candidate| candidate.key == entry.key)
        {
            entries.remove(position);
        }
        if entries.len() == self.capacity.get() {
            entries.pop_front();
            debug!(outcome = "evicted", "Alt-Svc origin evicted");
        }
        entries.push_back(entry);
        debug!(outcome = "stored", "updated Alt-Svc client state");
    }

    fn remove_key(&self, key: &StoreKey) {
        let mut entries = self.lock_entries();
        if let Some(position) = entries.iter().position(|entry| &entry.key == key) {
            entries.remove(position);
            debug!(outcome = "cleared", "removed Alt-Svc client state");
        }
    }

    fn lock_entries(&self) -> MutexGuard<'_, VecDeque<Entry>> {
        match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Returns the WHATWG ASCII serialization of an HTTPS origin.
///
/// Endpoint hosts are already canonical, so this matches
/// `url::Url::origin().ascii_serialization()` for the same origin.
fn canonical_origin(endpoint: &Endpoint) -> String {
    OriginKey::new(endpoint).serialize()
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct OriginKey {
    host: Box<str>,
    port: u16,
}

impl OriginKey {
    fn new(endpoint: &Endpoint) -> Self {
        Self {
            host: endpoint.host().to_ascii_lowercase().into(),
            port: endpoint.port(),
        }
    }

    /// Returns the WHATWG ASCII serialization of this HTTPS origin.
    fn serialize(&self) -> String {
        let host = &*self.host;
        let mut origin = if host.contains(':') {
            format!("https://[{host}]")
        } else {
            format!("https://{host}")
        };
        if self.port != 443 {
            origin.push_str(&format!(":{}", self.port));
        }
        origin
    }
}

/// Identity of one learned alternative: the origin it was advertised for and
/// the route that carried the advertisement.
///
/// An advertisement describes a location the client can reach over the path it
/// arrived on. A different route reaches a different network, or cannot carry
/// QUIC at all, so it must never reuse another route's alternative. The route
/// is therefore part of the key, exactly as it is in the H1, H2, and H3
/// connection pools.
#[derive(Clone, Debug, Eq, PartialEq)]
struct StoreKey {
    origin: OriginKey,
    route: Route,
}

impl StoreKey {
    fn new(endpoint: &Endpoint, route: &Route) -> Self {
        Self {
            origin: OriginKey::new(endpoint),
            route: route.clone(),
        }
    }

    /// Returns the direct-route key for an origin restored from a snapshot.
    const fn new_direct(origin: OriginKey) -> Self {
        Self {
            origin,
            route: Route::Direct,
        }
    }

    const fn origin(&self) -> &OriginKey {
        &self.origin
    }

    /// Returns whether this key names the direct route, the only route whose
    /// alternatives an [`AltSvcSnapshot`] describes.
    const fn is_direct(&self) -> bool {
        matches!(self.route, Route::Direct)
    }
}

struct BrokenRecord {
    key: StoreKey,
    location: AltSvcLocation,
    /// Failures since the alternative last connected.
    failures: u32,
    until: Instant,
}

struct Entry {
    key: StoreKey,
    location: AltSvcLocation,
    expires_at: Instant,
    generation: u64,
}

enum Update {
    Clear,
    Replace(Option<ParsedAlternative>),
}

struct ParsedAlternative {
    location: AltSvcLocation,
    max_age: u64,
    age: u64,
}

fn parse_response_fields<'a>(
    origin: &Endpoint,
    fields: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Result<Option<Update>, ()> {
    let mut values = Vec::new();
    let mut age = None;
    for (name, value) in fields {
        if name.eq_ignore_ascii_case("alt-svc") {
            values.push(value);
        } else if name.eq_ignore_ascii_case("age") {
            if age.is_some() {
                return Err(());
            }
            age = Some(parse_delta_seconds(trim_ows(value))?);
        }
    }
    if values.is_empty() {
        return Ok(None);
    }

    let mut combined = Vec::new();
    for value in values {
        if !combined.is_empty() {
            combined.extend_from_slice(b", ");
        }
        combined.extend_from_slice(value);
    }
    let members = split_members(&combined)?;
    if members.iter().any(|member| trim_ows(member) == b"clear") {
        return Ok(Some(Update::Clear));
    }

    let age = age.unwrap_or(0);
    let mut selected = None;
    for member in members {
        let alternative = parse_alternative(origin, trim_ows(member))?;
        if selected.is_none()
            && alternative
                .as_ref()
                .is_some_and(|candidate| candidate.max_age > age)
        {
            selected = alternative;
        }
    }
    if let Some(alternative) = selected.as_mut() {
        alternative.age = age;
    }
    Ok(Some(Update::Replace(selected)))
}

fn split_members(value: &[u8]) -> Result<Vec<&[u8]>, ()> {
    let mut members = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in value.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                if trim_ows(&value[start..index]).is_empty() {
                    return Err(());
                }
                members.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || escaped || trim_ows(&value[start..]).is_empty() {
        return Err(());
    }
    members.push(&value[start..]);
    Ok(members)
}

fn parse_alternative(origin: &Endpoint, value: &[u8]) -> Result<Option<ParsedAlternative>, ()> {
    let mut cursor = Cursor::new(value);
    let protocol = cursor.token().ok_or(())?;
    if !valid_protocol_id(protocol) {
        return Err(());
    }
    cursor.byte(b'=')?;
    let authority = cursor.quoted_string()?;
    let mut max_age = DEFAULT_MAX_AGE;
    let mut saw_max_age = false;

    loop {
        cursor.ows();
        if cursor.is_empty() {
            break;
        }
        cursor.byte(b';')?;
        cursor.ows();
        let name = cursor.token().ok_or(())?;
        cursor.byte(b'=')?;
        let (parameter, quoted) = cursor.token_or_quoted_string()?;
        if name.eq_ignore_ascii_case(b"ma") {
            if saw_max_age || quoted {
                return Err(());
            }
            max_age = parse_delta_seconds(&parameter)?;
            saw_max_age = true;
        }
    }

    let location = parse_location(origin, &authority)?;
    if protocol != b"h3" {
        return Ok(None);
    }
    Ok(Some(ParsedAlternative {
        location,
        max_age,
        age: 0,
    }))
}

fn parse_location(origin: &Endpoint, value: &[u8]) -> Result<AltSvcLocation, ()> {
    let value = std::str::from_utf8(value).map_err(|_| ())?;
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (literal, suffix) = bracketed.split_once(']').ok_or(())?;
        let port = suffix.strip_prefix(':').ok_or(())?;
        let host = literal.parse::<Ipv6Addr>().map_err(|_| ())?.to_string();
        (host.into_boxed_str(), parse_port(port)?)
    } else {
        let (host, port) = value.rsplit_once(':').ok_or(())?;
        if host.contains(':') {
            return Err(());
        }
        let host = if host.is_empty() {
            origin.host().into()
        } else {
            url::Host::parse(host)
                .map_err(|_| ())?
                .to_string()
                .into_boxed_str()
        };
        (host, parse_port(port)?)
    };
    Ok(AltSvcLocation { host, port })
}

fn parse_port(value: &str) -> Result<u16, ()> {
    let port = value.parse::<u16>().map_err(|_| ())?;
    (port != 0).then_some(port).ok_or(())
}

fn parse_delta_seconds(value: &[u8]) -> Result<u64, ()> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(());
    }
    Ok(value.iter().fold(0_u64, |parsed, byte| {
        parsed
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'))
            .min(MAX_DELTA_SECONDS)
    }))
}

fn expiration_at(now: Instant, maximum_seconds: u64) -> Instant {
    let mut lower = 0;
    let mut upper = maximum_seconds.min(MAX_DELTA_SECONDS);
    while lower < upper {
        let middle = lower + (upper - lower).div_ceil(2);
        if now.checked_add(Duration::from_secs(middle)).is_some() {
            lower = middle;
        } else {
            upper = middle - 1;
        }
    }
    now.checked_add(Duration::from_secs(lower)).unwrap_or(now)
}

fn valid_protocol_id(value: &[u8]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'%' {
            index += 1;
            continue;
        }
        let Some(encoded) = value.get(index + 1..index + 3) else {
            return false;
        };
        if !encoded
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
        {
            return false;
        }
        let decoded = hex_value(encoded[0]) * 16 + hex_value(encoded[1]);
        if decoded != b'%' && is_token_byte(decoded) {
            return false;
        }
        index += 3;
    }
    true
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(value: &'a [u8]) -> Self {
        Self { remaining: value }
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn ows(&mut self) {
        let length = self
            .remaining
            .iter()
            .take_while(|byte| matches!(**byte, b' ' | b'\t'))
            .count();
        self.remaining = &self.remaining[length..];
    }

    fn byte(&mut self, expected: u8) -> Result<(), ()> {
        if self.remaining.first() != Some(&expected) {
            return Err(());
        }
        self.remaining = &self.remaining[1..];
        Ok(())
    }

    fn token(&mut self) -> Option<&'a [u8]> {
        let length = self
            .remaining
            .iter()
            .take_while(|byte| is_token_byte(**byte))
            .count();
        if length == 0 {
            return None;
        }
        let (token, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Some(token)
    }

    fn token_or_quoted_string(&mut self) -> Result<(Vec<u8>, bool), ()> {
        if self.remaining.first() == Some(&b'"') {
            self.quoted_string().map(|value| (value, true))
        } else {
            self.token()
                .map(<[u8]>::to_vec)
                .map(|value| (value, false))
                .ok_or(())
        }
    }

    fn quoted_string(&mut self) -> Result<Vec<u8>, ()> {
        self.byte(b'"')?;
        let mut decoded = Vec::new();
        loop {
            let (&byte, remaining) = self.remaining.split_first().ok_or(())?;
            self.remaining = remaining;
            match byte {
                b'"' => return Ok(decoded),
                b'\\' => {
                    let (&escaped, remaining) = self.remaining.split_first().ok_or(())?;
                    if matches!(escaped, b'\r' | b'\n') {
                        return Err(());
                    }
                    self.remaining = remaining;
                    decoded.push(escaped);
                }
                b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff => {
                    decoded.push(byte);
                }
                _ => return Err(()),
            }
        }
    }
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Returns whether a failed alternative-service attempt invalidates the advertisement it used.
pub(crate) fn invalidates_alternative(error: &RequestError) -> bool {
    match error.kind() {
        RequestErrorKind::Resolve | RequestErrorKind::Connect | RequestErrorKind::Tls => true,
        RequestErrorKind::Timeout => matches!(
            error.timeout_phase(),
            Some(TimeoutPhase::Connect | TimeoutPhase::ResponseHead)
        ),
        RequestErrorKind::Http3 => std::error::Error::source(error)
            .and_then(|source| source.downcast_ref::<Http3ConnectorError>())
            .is_some_and(|error| {
                matches!(
                    error.kind(),
                    Http3ConnectorErrorKind::Endpoint
                        | Http3ConnectorErrorKind::Connect
                        | Http3ConnectorErrorKind::Connection
                        | Http3ConnectorErrorKind::Handshake
                        | Http3ConnectorErrorKind::Protocol
                )
            }),
        _ => false,
    }
}

#[cfg(feature = "https-records")]
mod https_records;
#[cfg(feature = "https-records")]
pub(crate) use https_records::{Discovery, HttpsRecordDiscovery, PendingLookup};

/// An HTTPS-record lookup; none can exist without the `https-records` feature.
#[cfg(not(feature = "https-records"))]
pub(crate) enum PendingLookup {}

#[cfg(not(feature = "https-records"))]
impl PendingLookup {
    pub(crate) async fn advertises_h3(self) -> bool {
        match self {}
    }
}

mod policy;
pub use policy::{AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace};

mod snapshot;
pub use snapshot::{
    AltSvcSnapshot, AltSvcSnapshotEntry, AltSvcSnapshotError, AltSvcSnapshotErrorKind,
};

#[cfg(test)]
mod tests;
