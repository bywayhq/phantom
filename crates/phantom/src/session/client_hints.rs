use std::{
    collections::{HashSet, VecDeque},
    num::NonZeroUsize,
    sync::{Mutex, MutexGuard},
};

use http::{HeaderMap, header::HeaderName};
use phantom_net::request::{RequestBody, RequestHeader};
use phantom_profile::{ClientHintDelivery, ClientHintSettings, request_template::ClientHintSlot};
use sfv::{BareItem, List, ListEntry, Parser};
use tracing::debug;

use crate::{PreparedRequestTemplate, RequestError, authority::Endpoint};

const ACCEPT_CH: HeaderName = HeaderName::from_static("accept-ch");
const CRITICAL_CH: HeaderName = HeaderName::from_static("critical-ch");

/// The client hints of one request, fixed when its field lists are built.
///
/// Chromium sets a request's hints as request fields before it asks for a
/// connection, so a hint that a response teaches in the meantime reaches the
/// next request, not this one. A connection's ALPS `ACCEPT_CH` adds nothing
/// to a list already built: it restarts the request instead (see
/// [`Self::connection_restart`]).
#[derive(Clone, Copy)]
pub(crate) struct ClientHintContext<'a> {
    endpoint: &'a Endpoint,
    origin: &'a str,
    settings: &'a ClientHintSettings,
    store: Option<&'a ClientHintStore>,
    template: Option<&'a PreparedRequestTemplate>,
    restart: &'a [usize],
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
            restart: &[],
        }
    }

    /// Places automatic hints at the template's client-hint slots.
    pub(crate) fn with_template(mut self, template: Option<&'a PreparedRequestTemplate>) -> Self {
        self.template = template;
        self
    }

    /// Adds the hints that connections' `ACCEPT_CH` restarted the request
    /// for.
    pub(crate) fn with_restart_hints(mut self, restart: &'a RestartHints) -> Self {
        self.restart = &restart.indices;
        self
    }

    pub(crate) fn origin(self) -> &'a str {
        self.origin
    }

    fn is_https(self) -> bool {
        self.origin.starts_with("https://")
    }

    /// Adds the enabled client hints to `caller`: the default hints, those
    /// the origin requested through `Accept-CH` so far, and the restart
    /// hints.
    ///
    /// # Errors
    ///
    /// Returns a request-template error when the template does not capture
    /// where requested hints go, or has no client-hint slot, and a hint
    /// requested through `Accept-CH` or ALPS `ACCEPT_CH`, or supplied by the
    /// caller, would be sent.
    pub(crate) fn prepare(
        self,
        caller: Vec<RequestHeader>,
    ) -> Result<Vec<RequestHeader>, RequestError> {
        let stored = self.store.and_then(|store| {
            store.active_indices(&OriginKey::new(self.endpoint, self.is_https()))
        });
        let prepared = prepare_fields(
            self.settings,
            stored.as_deref(),
            Some(self.restart),
            caller,
            self.template,
        );
        // A template without slots places no hint; `check` already refused
        // default hints for it, so only requested hints remain.
        let unplaced = self.template.is_some_and(|template| {
            !template.requested_client_hint_placement() || template.client_hint_slots().is_empty()
        });
        if unplaced && sends_requested_hint(self.settings, &prepared) {
            return Err(RequestError::request_template_requested_hint());
        }
        Ok(prepared)
    }

    /// Returns the hints a connection's ALPS `ACCEPT_CH` asks for that `sent`
    /// lacks, when the request must restart to carry them.
    ///
    /// Chromium checks a connection's `ACCEPT_CH` once the request has a
    /// stream and before it writes the request. When the entry names a hint
    /// the request lacks, the browser abandons that request unsent and starts
    /// it again with the hint (`AcceptCHFrameInterceptor::OnConnected`,
    /// `services/network/accept_ch_frame_interceptor.cc` lines 90-146, called
    /// from `URLLoader::ProcessAcceptCHFrameOnConnected`,
    /// `services/network/url_loader.cc` lines 920-942;
    /// `NavigationURLLoaderImpl::OnAcceptCHFrameReceived`,
    /// `content/browser/loader/navigation_url_loader_impl.cc` lines
    /// 1757-1923 at tag `154.0.8037.58`). The entry teaches the origin
    /// nothing: the browser computes the restarted request's hints with the
    /// entry's hints added and clears them again (`:1838-1846`).
    ///
    /// Only a navigation restarts: a template whose
    /// `restarts_for_connection_accept_ch` is `false`, such as a `fetch`, goes
    /// out as built. A request without a template is a top-level one.
    ///
    /// An empty or malformed entry asks for nothing, and neither does a width
    /// hint, which Chromium leaves out because only images send it
    /// (`accept_ch_frame_interceptor.cc` lines 38-43). When every missing hint
    /// is one the origin requested through `Accept-CH` by now, the request
    /// goes out as built: the browser restarts only for a hint that is not
    /// enabled for the origin (`AcceptCHFrameInterceptor::NeedsObserverCheck`,
    /// lines 159-200; `GetCriticalHintsMissingStatus`,
    /// `content/browser/client_hints/client_hints.cc` lines 1074-1098). A hint
    /// this request already restarted for is not asked for again, so restarts
    /// end after at most one per hint the profile sends on request.
    pub(crate) fn connection_restart(
        self,
        sent: &[RequestHeader],
        connection_accept_ch: Option<&[u8]>,
    ) -> Option<Box<[usize]>> {
        if self
            .template
            .is_some_and(|template| !template.restarts_for_connection_accept_ch())
        {
            return None;
        }
        let value = connection_accept_ch.filter(|value| !value.is_empty())?;
        let tokens = match std::str::from_utf8(value)
            .map_err(|_| ())
            .and_then(parse_token_list)
        {
            Ok(tokens) => tokens,
            Err(()) => {
                debug!(outcome = "malformed", "ignored ALPS ACCEPT_CH value");
                return None;
            }
        };
        let missing: Vec<usize> = requested_indices(self.settings, &tokens)
            .iter()
            .copied()
            .filter(|index| {
                let name = self.settings.hints()[*index].name();
                !is_width_hint(name) && !contains_field(sent, name)
            })
            .collect();
        let stored = self.store.and_then(|store| {
            store.stored_indices(&OriginKey::new(self.endpoint, self.is_https()))
        });
        let enabled_now = |index: &usize| {
            stored
                .as_deref()
                .is_some_and(|stored| stored.contains(index))
        };
        if missing.iter().all(enabled_now) {
            return None;
        }
        let added: Box<[usize]> = missing
            .into_iter()
            .filter(|index| !self.restart.contains(index))
            .collect();
        (!added.is_empty()).then_some(added)
    }
}

/// Whether `name` is a width hint, which only image requests send.
fn is_width_hint(name: &str) -> bool {
    name.eq_ignore_ascii_case("sec-ch-width") || name.eq_ignore_ascii_case("width")
}

/// The hints that connections' ALPS `ACCEPT_CH` restarted one request for,
/// in the order the restarts added them.
///
/// They only accumulate: Chromium merges each restart's hints into the
/// request's fields (`navigation_url_loader_impl.cc` line 1904 at tag
/// `154.0.8037.58`), so a later restart keeps the earlier ones, and a name
/// the fields lack is appended after them (`HttpRequestHeaders::MergeFrom`
/// and `SetHeaderInternal`, `net/http/http_request_headers.cc` lines
/// 191-195 and 303-310).
#[derive(Clone, Debug, Default)]
pub(crate) struct RestartHints {
    /// Profile hint indices, in the order they were added.
    indices: Vec<usize>,
    /// How many restarts added them.
    restarts: usize,
}

impl RestartHints {
    /// Records one restart's hints and returns how many restarts there were.
    pub(crate) fn add(&mut self, hints: &[usize]) -> usize {
        for hint in hints {
            if !self.indices.contains(hint) {
                self.indices.push(*hint);
            }
        }
        self.restarts += 1;
        self.restarts
    }
}

/// A request that stopped before any of it was written, because its
/// connection's ALPS `ACCEPT_CH` asks for hints the request lacks.
pub(crate) struct AcceptChRestart {
    /// Profile hint indices to add; see [`ClientHintContext::connection_restart`].
    pub(crate) hints: Box<[usize]>,
    /// The request body, not polled, for the restarted request.
    pub(crate) body: Option<RequestBody>,
}

/// What a dispatch did with its request.
pub(crate) enum Dispatched<T> {
    /// The request was sent, with its outcome.
    Sent(T),
    /// The request must restart with more client hints; nothing was sent.
    Restart(AcceptChRestart),
}

impl<T> Dispatched<T> {
    pub(crate) fn map<U>(self, sent: impl FnOnce(T) -> U) -> Dispatched<U> {
        match self {
            Self::Sent(outcome) => Dispatched::Sent(sent(outcome)),
            Self::Restart(restart) => Dispatched::Restart(restart),
        }
    }
}

/// Returns whether `fields` carry a hint the profile sends only on request.
fn sends_requested_hint(settings: &ClientHintSettings, fields: &[RequestHeader]) -> bool {
    fields.iter().any(|field| {
        settings.hints().iter().any(|hint| {
            hint.delivery() != ClientHintDelivery::Default
                && hint.name().eq_ignore_ascii_case(field.name())
        })
    })
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

    /// Returns the hints `origin` requested, without marking it recently used.
    fn stored_indices(&self, origin: &OriginKey) -> Option<Box<[usize]>> {
        self.lock_entries()
            .iter()
            .find(|entry| &entry.origin == origin)
            .map(|entry| entry.requested.clone())
    }

    #[cfg(test)]
    pub(super) fn prepare(
        &self,
        endpoint: &Endpoint,
        settings: &ClientHintSettings,
        caller: Vec<RequestHeader>,
    ) -> Vec<RequestHeader> {
        let origin = OriginKey::new(endpoint, true);
        let active = self.active_indices(&origin);
        prepare_fields(settings, active.as_deref(), None, caller, None)
    }

    pub(super) fn learn_and_should_retry(
        &self,
        endpoint: &Endpoint,
        https: bool,
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

        self.replace(OriginKey::new(endpoint, https), requested);
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
    restart: Option<&[usize]>,
    caller: Vec<RequestHeader>,
    template: Option<&PreparedRequestTemplate>,
) -> Vec<RequestHeader> {
    let enabled = |index: usize| {
        settings.hints()[index].delivery() == ClientHintDelivery::Default
            || stored.is_some_and(|indices| indices.binary_search(&index).is_ok())
    };
    let slots = template.map_or(&[][..], PreparedRequestTemplate::client_hint_slots);
    let mut prepared = if slots.is_empty() {
        place_before_caller(settings, enabled, caller)
    } else {
        place_in_slots(settings, slots, enabled, caller)
    };
    // A hint only a restart added follows every other field, where
    // Chromium's merge appends a new name; a stored one keeps its slot.
    for index in restart.unwrap_or_default() {
        let hint = &settings.hints()[*index];
        if !enabled(*index) && !contains_field(&prepared, hint.name()) {
            prepared.push(RequestHeader::new(hint.name(), hint.value()));
        }
    }
    prepared
}

/// Puts the enabled hints in profile order before the caller's fields,
/// leaving out any hint the caller supplies.
fn place_before_caller(
    settings: &ClientHintSettings,
    enabled: impl Fn(usize) -> bool,
    caller: Vec<RequestHeader>,
) -> Vec<RequestHeader> {
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
    slots: &[ClientHintSlot],
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
/// An origin's scheme, host, and port. Loopback and `localhost` origins
/// learn hints over `http://` too, so the scheme separates them from the
/// HTTPS origin on the same host and port.
struct OriginKey {
    https: bool,
    host: Box<str>,
    port: u16,
}

impl OriginKey {
    fn new(endpoint: &Endpoint, https: bool) -> Self {
        Self {
            https,
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
