use std::{
    collections::{HashSet, VecDeque},
    num::NonZeroUsize,
    sync::{Mutex, MutexGuard},
};

use http::{HeaderMap, header::HeaderName};
use phantom_net::request::RequestHeader;
use phantom_profile::{
    ClientHintDelivery, ClientHintSettings, RequestTemplate,
    request_template::client_hint_placement,
};
use sfv::{BareItem, List, ListEntry, Parser};
use tracing::debug;

use crate::authority::Endpoint;

const ACCEPT_CH: HeaderName = HeaderName::from_static("accept-ch");
const CRITICAL_CH: HeaderName = HeaderName::from_static("critical-ch");

#[derive(Clone, Copy)]
pub(crate) struct ClientHintContext<'a> {
    endpoint: &'a Endpoint,
    origin: &'a str,
    settings: &'a ClientHintSettings,
    store: Option<&'a ClientHintStore>,
    template: Option<&'a RequestTemplate>,
}

impl<'a> ClientHintContext<'a> {
    pub(super) fn new(
        endpoint: &'a Endpoint,
        origin: &'a str,
        settings: &'a ClientHintSettings,
        store: Option<&'a ClientHintStore>,
    ) -> Self {
        Self {
            endpoint,
            origin,
            settings,
            store,
            template: None,
        }
    }

    /// Places automatic hints at the template's client-hint slots.
    pub(crate) fn with_template(mut self, template: Option<&'a RequestTemplate>) -> Self {
        self.template = template;
        self
    }

    pub(crate) fn origin(self) -> &'a str {
        self.origin
    }

    pub(crate) fn prepare(
        self,
        caller: Vec<RequestHeader>,
        connection_accept_ch: Option<&[u8]>,
    ) -> Vec<RequestHeader> {
        let stored = self
            .store
            .and_then(|store| store.active_indices(&OriginKey::new(self.endpoint)));
        let connection = connection_accept_ch.and_then(|value| match std::str::from_utf8(value) {
            Ok(value) => match parse_token_list(value) {
                Ok(tokens) => Some(requested_indices(self.settings, &tokens)),
                Err(()) => {
                    debug!(outcome = "malformed", "ignored ALPS ACCEPT_CH value");
                    None
                }
            },
            Err(_) => {
                debug!(outcome = "malformed", "ignored ALPS ACCEPT_CH value");
                None
            }
        });
        prepare_fields(
            self.settings,
            stored.as_deref(),
            connection.as_deref(),
            caller,
            self.template,
        )
    }
}

pub(super) struct ClientHintStore {
    capacity: NonZeroUsize,
    entries: Mutex<VecDeque<Entry>>,
}

impl ClientHintStore {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::new()),
        }
    }

    pub(super) const fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    pub(super) fn clear(&self) {
        self.lock_entries().clear();
    }

    #[cfg(test)]
    pub(super) fn prepare(
        &self,
        endpoint: &Endpoint,
        settings: &ClientHintSettings,
        caller: Vec<RequestHeader>,
    ) -> Vec<RequestHeader> {
        let origin = OriginKey::new(endpoint);
        let active = self.active_indices(&origin);
        prepare_fields(settings, active.as_deref(), None, caller, None)
    }

    pub(super) fn learn_and_should_retry(
        &self,
        endpoint: &Endpoint,
        settings: &ClientHintSettings,
        response: &HeaderMap,
        sent: &[RequestHeader],
    ) -> bool {
        let Some(accept_ch) = parse_header(response, &ACCEPT_CH) else {
            return false;
        };
        let requested = match accept_ch {
            Ok(tokens) => requested_indices(settings, &tokens),
            Err(()) => {
                debug!(outcome = "malformed", "ignored Accept-CH response field");
                return false;
            }
        };
        let critical = parse_header(response, &CRITICAL_CH)
            .and_then(Result::ok)
            .unwrap_or_default();
        let should_retry = requested.iter().any(|index| {
            critical.contains(settings.hints()[*index].name())
                && !contains_field(sent, settings.hints()[*index].name())
        });

        self.replace(OriginKey::new(endpoint), requested);
        should_retry
    }

    fn active_indices(&self, origin: &OriginKey) -> Option<Box<[usize]>> {
        let mut entries = self.lock_entries();
        let position = entries.iter().position(|entry| &entry.origin == origin)?;
        let entry = entries.remove(position)?;
        let active = entry.requested.clone();
        entries.push_back(entry);
        Some(active)
    }

    fn replace(&self, origin: OriginKey, requested: Box<[usize]>) {
        let mut entries = self.lock_entries();
        if let Some(position) = entries.iter().position(|entry| entry.origin == origin) {
            entries.remove(position);
        }
        if requested.is_empty() {
            debug!(outcome = "cleared", "updated Accept-CH client state");
            return;
        }
        if entries.len() == self.capacity.get() {
            entries.pop_front();
            debug!(outcome = "evicted", "client-hint origin evicted");
        }
        debug!(
            outcome = "stored",
            hint_count = requested.len(),
            "updated Accept-CH client state"
        );
        entries.push_back(Entry { origin, requested });
    }

    fn lock_entries(&self) -> MutexGuard<'_, VecDeque<Entry>> {
        match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
pub(crate) fn prepare_default_fields(
    settings: &ClientHintSettings,
    caller: Vec<RequestHeader>,
) -> Vec<RequestHeader> {
    prepare_fields(settings, None, None, caller, None)
}

fn prepare_fields(
    settings: &ClientHintSettings,
    stored: Option<&[usize]>,
    connection: Option<&[usize]>,
    caller: Vec<RequestHeader>,
    template: Option<&RequestTemplate>,
) -> Vec<RequestHeader> {
    let enabled = |index: usize| {
        settings.hints()[index].delivery() == ClientHintDelivery::Default
            || stored.is_some_and(|indices| indices.binary_search(&index).is_ok())
            || connection.is_some_and(|indices| indices.binary_search(&index).is_ok())
    };
    // Any protocol's list works: validation requires the same placement on
    // every protocol.
    let slots = template.map(|template| client_hint_placement(&template.http2_fields));
    if let Some(slots) = slots.filter(|slots| !slots.is_empty()) {
        return place_in_slots(settings, &slots, enabled, caller);
    }

    let caller_names = caller
        .iter()
        .map(|header| header.name().to_ascii_lowercase().into_boxed_str())
        .collect::<HashSet<_>>();
    let mut prepared = Vec::with_capacity(settings.hints().len() + caller.len());

    for (index, hint) in settings.hints().iter().enumerate() {
        if enabled(index) && !caller_names.contains(hint.name()) {
            prepared.push(RequestHeader::new(hint.name(), hint.value()));
        }
    }
    prepared.extend(caller);
    prepared
}

/// Rebuilds each client-hint slot of an expanded template field list.
///
/// Caller fields for a slot's hints keep their values; other enabled hints
/// get the profile value. Each slot's fields are inserted before the first
/// present field that follows the slot in the template. Every field that
/// validation guarantees follows a slot ends with a literal the expansion
/// always emits, so a slot never lands after caller-only or cookie fields.
fn place_in_slots(
    settings: &ClientHintSettings,
    slots: &[phantom_profile::ClientHintSlot],
    enabled: impl Fn(usize) -> bool,
    caller: Vec<RequestHeader>,
) -> Vec<RequestHeader> {
    let single: Vec<&str> = slots
        .iter()
        .filter_map(|slot| slot.hint.as_deref())
        .collect();
    let is_hint = |name: &str| {
        single
            .iter()
            .any(|single| single.eq_ignore_ascii_case(name))
            || settings
                .hints()
                .iter()
                .any(|hint| hint.name().eq_ignore_ascii_case(name))
    };
    let (mut supplied, mut fields): (Vec<_>, Vec<_>) = caller
        .into_iter()
        .partition(|header| is_hint(header.name()));

    for slot in slots {
        let names: Vec<&str> = match &slot.hint {
            Some(name) => vec![name],
            None => settings
                .hints()
                .iter()
                .map(|hint| hint.name())
                .filter(|name| !single.contains(name))
                .collect(),
        };
        let mut group = Vec::new();
        for name in names {
            let before = group.len();
            supplied.retain(|header| {
                let matches = header.name().eq_ignore_ascii_case(name);
                if matches {
                    group.push(header.clone());
                }
                !matches
            });
            if group.len() == before {
                let automatic = settings
                    .hints()
                    .iter()
                    .enumerate()
                    .find(|(index, hint)| hint.name() == name && enabled(*index));
                if let Some((_, hint)) = automatic {
                    group.push(RequestHeader::new(hint.name(), hint.value()));
                }
            }
        }
        let position = slot
            .followed_by
            .iter()
            .find_map(|next| {
                fields
                    .iter()
                    .position(|header| header.name().eq_ignore_ascii_case(next))
            })
            .unwrap_or(fields.len());
        fields.splice(position..position, group);
    }
    // Validation gives every profile hint a slot; keep any other caller field.
    fields.extend(supplied);
    fields
}

fn requested_indices(settings: &ClientHintSettings, tokens: &HashSet<Box<str>>) -> Box<[usize]> {
    settings
        .hints()
        .iter()
        .enumerate()
        .filter_map(|(index, hint)| {
            (hint.delivery() == ClientHintDelivery::AcceptCh && tokens.contains(hint.name()))
                .then_some(index)
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn contains_field(headers: &[RequestHeader], name: &str) -> bool {
    headers
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case(name))
}

fn parse_header(headers: &HeaderMap, name: &HeaderName) -> Option<Result<HashSet<Box<str>>, ()>> {
    let values = headers.get_all(name);
    let mut iter = values.iter();
    let first = iter.next()?;
    let mut combined = Vec::with_capacity(first.as_bytes().len());
    combined.extend_from_slice(first.as_bytes());
    for value in iter {
        combined.extend_from_slice(b", ");
        combined.extend_from_slice(value.as_bytes());
    }
    let text = std::str::from_utf8(&combined).map_err(|_| ());
    Some(text.and_then(parse_token_list))
}

fn parse_token_list(value: &str) -> Result<HashSet<Box<str>>, ()> {
    if value.trim().is_empty() {
        return Ok(HashSet::new());
    }
    let list: List = Parser::new(value).parse().map_err(|_| ())?;
    let mut tokens = HashSet::with_capacity(list.len());
    for entry in list {
        let ListEntry::Item(item) = entry else {
            return Err(());
        };
        let BareItem::Token(token) = item.bare_item else {
            return Err(());
        };
        tokens.insert(token.as_str().to_ascii_lowercase().into_boxed_str());
    }
    Ok(tokens)
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
    requested: Box<[usize]>,
}

#[cfg(test)]
#[path = "client_hints/tests.rs"]
mod tests;
