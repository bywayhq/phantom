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

use phantom_net::OrderedResponseHeaders;
use tracing::debug;

use crate::authority::Endpoint;

const DEFAULT_MAX_AGE: u64 = 24 * 60 * 60;
const MAX_DELTA_SECONDS: u64 = 1 << 31;

pub(super) struct AltSvcSelection {
    location: AltSvcLocation,
    generation: u64,
}

impl AltSvcSelection {
    pub(super) fn location(&self) -> &AltSvcLocation {
        &self.location
    }

    pub(super) const fn generation(&self) -> u64 {
        self.generation
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AltSvcLocation {
    host: Box<str>,
    port: u16,
}

impl AltSvcLocation {
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
    next_generation: AtomicU64,
}

impl AltSvcStore {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::new()),
            next_generation: AtomicU64::new(1),
        }
    }

    pub(super) const fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    pub(super) fn learn(&self, origin: &Endpoint, headers: &OrderedResponseHeaders) {
        self.learn_fields_at(
            origin,
            headers.iter().map(|field| (field.name(), field.value())),
            Instant::now(),
        );
    }

    pub(super) fn get(&self, origin: &Endpoint) -> Option<AltSvcSelection> {
        self.get_at(origin, Instant::now())
    }

    #[cfg(test)]
    fn remove(&self, origin: &Endpoint) {
        self.remove_key(&OriginKey::new(origin));
    }

    pub(super) fn remove_if_current(&self, origin: &Endpoint, generation: u64) {
        let key = OriginKey::new(origin);
        let mut entries = self.lock_entries();
        if let Some(position) = entries
            .iter()
            .position(|entry| entry.origin == key && entry.generation == generation)
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
    }

    fn learn_fields_at<'a>(
        &self,
        origin: &Endpoint,
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
        let key = OriginKey::new(origin);
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
                    origin: key,
                    location: alternative.location,
                    expires_at,
                    generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
                });
            }
        }
    }

    fn get_at(&self, origin: &Endpoint, now: Instant) -> Option<AltSvcSelection> {
        let key = OriginKey::new(origin);
        let mut entries = self.lock_entries();
        let position = entries.iter().position(|entry| entry.origin == key)?;
        let entry = entries.remove(position)?;
        if entry.expires_at <= now {
            debug!(outcome = "expired", "removed expired Alt-Svc origin");
            return None;
        }
        let selection = AltSvcSelection {
            location: entry.location.clone(),
            generation: entry.generation,
        };
        entries.push_back(entry);
        Some(selection)
    }

    fn replace(&self, entry: Entry) {
        let mut entries = self.lock_entries();
        if let Some(position) = entries
            .iter()
            .position(|candidate| candidate.origin == entry.origin)
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

    fn remove_key(&self, origin: &OriginKey) {
        let mut entries = self.lock_entries();
        if let Some(position) = entries.iter().position(|entry| &entry.origin == origin) {
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

#[derive(Clone, Debug, Eq, PartialEq)]
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
}

struct Entry {
    origin: OriginKey,
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

#[cfg(test)]
mod tests;
