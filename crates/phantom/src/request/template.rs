//! Expansion and checks for browser request templates.

use std::{fmt, sync::Arc};

use phantom_net::request::RequestHeader;
use phantom_profile::{
    ClientHintDelivery, ClientHintSettings, ClientHintSlot, Http2Priority, InvalidRequestTemplate,
    ProxyAuthorizationAttempt, RequestField, RequestTemplate, client_hint_placement,
    restart_client_hint_placement,
};

use crate::{HttpProtocol, RequestError};

/// A validated request template that requests share without copying it.
///
/// [`PreparedRequestTemplate::new`] validates the template once. Pass the
/// result to [`RequestBuilder::template`](crate::RequestBuilder::template)
/// for each request; cloning it copies a reference count, not the fields.
/// A profile's default template is prepared once while building the client.
/// Debug output shows structural counts and omits header names and values.
#[derive(Clone)]
pub struct PreparedRequestTemplate(Arc<Prepared>);

struct Prepared {
    template: RequestTemplate,
    /// Client-hint placement, the same on every protocol list.
    client_hint_slots: Vec<ClientHintSlot>,
    /// The fields that follow the restart client-hints slot, the same on
    /// every protocol list, or `None` without one.
    restart_client_hint_slot: Option<Vec<Box<str>>>,
    /// The HTTP/1.1 list's values by forwarding state, then URL trust.
    accept_encoding: [[Option<Box<str>>; 2]; 2],
    /// Whether every protocol list sends the same `Accept-Encoding` value to
    /// both kinds of URL, separately for each forwarding state.
    accept_encoding_agrees: [bool; 2],
}

impl fmt::Debug for PreparedRequestTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let template = &self.0.template;
        formatter
            .debug_struct("PreparedRequestTemplate")
            .field("http1_field_count", &template.http1_fields.len())
            .field("http2_field_count", &template.http2_fields.len())
            .field(
                "http3_field_count",
                &template.http3_fields.as_ref().map(Vec::len),
            )
            .field("client_hint_slot_count", &self.0.client_hint_slots.len())
            .field(
                "restart_client_hint_slot",
                &self.0.restart_client_hint_slot.is_some(),
            )
            .field(
                "requested_client_hint_placement",
                &template.requested_client_hint_placement,
            )
            .finish_non_exhaustive()
    }
}

impl PreparedRequestTemplate {
    /// Validates `template` and prepares it for sending.
    ///
    /// # Errors
    ///
    /// Returns the error of [`RequestTemplate::validate`] when the template
    /// data is invalid.
    pub fn new(template: RequestTemplate) -> Result<Self, InvalidRequestTemplate> {
        template.validate()?;
        Ok(Self::prepare(template))
    }

    /// Returns this template without the credential fields it sends itself,
    /// for the hops after a cross-origin redirect.
    ///
    /// Fetch's HTTP-redirect fetch, step 13, deletes `Authorization` from a
    /// request whose redirect leaves the origin, whoever set it; Chromium 154
    /// does so in `ResourceLoader::WillFollowRedirect`
    /// (`third_party/blink/renderer/platform/loader/fetch/resource_loader.cc`
    /// lines 541-548). A browser's own fields never carry credentials, so a
    /// template's credential field stands for one the page set, and it goes
    /// with the caller's fields of the same names, which the redirect state
    /// removes. Caller slots for those names go too, so a required one is
    /// not left without the field it names.
    pub(crate) fn without_credentials(&self) -> Self {
        let keeps = |field: &RequestField| match field {
            RequestField::Literal { name, .. }
            | RequestField::ByTrust { name, .. }
            | RequestField::ByForwarding { name, .. }
            | RequestField::Caller { name, .. } => !crate::redirect::is_credential_header(name),
            _ => true,
        };
        if lists(&self.0.template).flatten().all(keeps) {
            return self.clone();
        }
        let mut template = self.0.template.clone();
        template.http1_fields.retain(keeps);
        template.http2_fields.retain(keeps);
        if let Some(fields) = &mut template.http3_fields {
            fields.retain(keeps);
        }
        Self::prepare(template)
    }

    /// Computes the placement data of a valid template.
    fn prepare(template: RequestTemplate) -> Self {
        let client_hint_slots = client_hint_placement(&template.http2_fields);
        let restart_client_hint_slot = restart_client_hint_placement(&template.http2_fields);
        let mut accept_encoding = [[None, None], [None, None]];
        let mut accept_encoding_agrees = [true; 2];
        for forwarded in [false, true] {
            for trustworthy in [false, true] {
                let mut codings = lists(&template).map(|fields| {
                    default_value_on_route(fields, "accept-encoding", trustworthy, forwarded)
                });
                let first = codings.next().flatten();
                accept_encoding_agrees[usize::from(forwarded)] &=
                    codings.all(|coding| coding == first);
                accept_encoding[usize::from(forwarded)][usize::from(trustworthy)] =
                    first.map(Box::from);
            }
        }
        Self(Arc::new(Prepared {
            template,
            client_hint_slots,
            restart_client_hint_slot,
            accept_encoding,
            accept_encoding_agrees,
        }))
    }

    /// Returns the template's field list for `protocol`, if one was captured.
    pub(crate) fn fields_for(&self, protocol: HttpProtocol) -> Option<&[RequestField]> {
        let template = &self.0.template;
        match protocol {
            HttpProtocol::Http1 => Some(&template.http1_fields),
            HttpProtocol::Http2 => Some(&template.http2_fields),
            HttpProtocol::Http3 => template.http3_fields.as_deref(),
        }
    }

    /// Returns each client-hint slot with the fields that follow it.
    pub(crate) fn client_hint_slots(&self) -> &[ClientHintSlot] {
        &self.0.client_hint_slots
    }

    /// Returns the fields that follow the slot where hints added by an
    /// `ACCEPT_CH` restart go, if the template has one.
    pub(crate) fn restart_client_hint_slot(&self) -> Option<&[Box<str>]> {
        self.0.restart_client_hint_slot.as_deref()
    }

    pub(crate) fn requested_client_hint_placement(&self) -> bool {
        self.0.template.requested_client_hint_placement
    }

    pub(crate) fn restarts_for_connection_accept_ch(&self) -> bool {
        self.0.template.restarts_for_connection_accept_ch
    }

    pub(crate) fn http2_priority(&self) -> Option<Http2Priority> {
        self.0.template.http2_priority
    }

    /// Returns the value the template's HTTP/1.1 list sends in the field
    /// `name` to a URL of this trust when the caller supplies none.
    pub(crate) fn default_field_value(&self, name: &str, trustworthy: bool) -> Option<&str> {
        default_value(&self.0.template.http1_fields, name, trustworthy)
    }

    /// Returns the `Accept-Encoding` value the template sends to a URL of
    /// this trust and forwarding state, before the protocol is chosen.
    pub(crate) fn accept_encoding(&self, trustworthy: bool, forwarded: bool) -> Option<&str> {
        self.0.accept_encoding[usize::from(forwarded)][usize::from(trustworthy)].as_deref()
    }
}

/// How the request reaches its origin, for route-dependent template entries.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Forwarding<'a> {
    /// Whether an HTTP proxy forwards the request: absolute form on HTTP/1.1,
    /// `:scheme` `http` on an HTTP/2 proxy connection.
    pub(crate) forwarded: bool,
    /// The generated `Proxy-Authorization` field this forwarded attempt
    /// carries, if any.
    pub(crate) credentials: Option<ForwardedCredentials<'a>>,
}

/// The generated `Proxy-Authorization` field of one forwarded attempt.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ForwardedCredentials<'a> {
    pub(crate) field: &'a RequestHeader,
    /// [`ProxyAuthorizationAttempt::Preemptive`] or
    /// [`ProxyAuthorizationAttempt::Replay`].
    pub(crate) attempt: ProxyAuthorizationAttempt,
}

/// Emits the template's fields in order with the caller's fields in place,
/// for a request that no HTTP proxy forwards.
#[cfg(test)]
pub(crate) fn expand(
    fields: &[RequestField],
    caller: &[RequestHeader],
    hints: Option<&ClientHintSettings>,
    trustworthy: bool,
) -> Vec<RequestHeader> {
    expand_on_route(fields, caller, hints, trustworthy, Forwarding::default()).0
}

/// Emits the template's fields in order with the caller's fields in place.
///
/// A caller field whose name matches a literal, trust-dependent,
/// forwarding-dependent, caller, or client-hint slot takes that slot's
/// position and spelling, keeping its value and sensitivity; a literal with
/// no caller field emits its captured value, a trust-dependent entry the
/// value for `trustworthy`, and a forwarding-dependent entry the value for
/// `route.forwarded`, if any. Caller fields for profile client hints fill the
/// client-hints slot in profile order. Automatic client hints are added
/// later, once the connection is chosen. Every other caller field follows
/// the template in the caller's order.
///
/// The generated credentials in `route` take the first
/// [`RequestField::ProxyAuthorization`] slot whose attempts cover theirs,
/// with the slot's spelling and the field's sensitivity. The returned flag
/// tells whether a slot placed them; the caller appends them otherwise.
/// Without generated credentials, a forwarded request's caller field of that
/// name takes the first slot that covers a preemptive attempt.
#[cfg(test)]
pub(crate) fn expand_on_route(
    fields: &[RequestField],
    caller: &[RequestHeader],
    hints: Option<&ClientHintSettings>,
    trustworthy: bool,
    route: Forwarding<'_>,
) -> (Vec<RequestHeader>, bool) {
    expand_on_route_with_managed_headers(fields, caller, hints, trustworthy, route, &[])
}

pub(crate) fn expand_on_route_with_managed_headers(
    fields: &[RequestField],
    caller: &[RequestHeader],
    hints: Option<&ClientHintSettings>,
    trustworthy: bool,
    route: Forwarding<'_>,
    managed: &[&str],
) -> (Vec<RequestHeader>, bool) {
    let mut credentials = route.credentials;
    let mut used = vec![false; caller.len()];
    let mut expanded = Vec::with_capacity(fields.len() + caller.len());
    let slotted: Vec<&str> = fields
        .iter()
        .filter_map(|field| match field {
            RequestField::ClientHint { name } => Some(&**name),
            _ => None,
        })
        .collect();
    let mut place = |name: &str, expanded: &mut Vec<RequestHeader>| {
        let mut placed = false;
        for (header, used) in caller.iter().zip(&mut used) {
            if !*used && header.name().eq_ignore_ascii_case(name) {
                *used = true;
                placed = true;
                expanded.push(respelled(name, header));
            }
        }
        placed
    };
    for field in fields {
        match field {
            RequestField::Literal { name, .. } | RequestField::ByTrust { name, .. } => {
                if !place(name, &mut expanded)
                    && let Some(value) = field.default_value(if trustworthy {
                        phantom_profile::UrlTrust::PotentiallyTrustworthy
                    } else {
                        phantom_profile::UrlTrust::Untrustworthy
                    })
                {
                    expanded.push(RequestHeader::new(&**name, value.as_bytes()));
                }
            }
            RequestField::ByForwarding {
                name,
                unforwarded,
                forwarded,
            } => {
                let value = if route.forwarded {
                    forwarded
                } else {
                    unforwarded
                };
                if !place(name, &mut expanded)
                    && let Some(value) = value
                {
                    expanded.push(RequestHeader::new(&**name, value.as_bytes()));
                }
            }
            RequestField::ProxyAuthorization { name, attempt } => {
                if let Some(generated) =
                    credentials.take_if(|generated| attempt.covers(generated.attempt))
                {
                    expanded.push(respelled(name, generated.field));
                } else if route.forwarded
                    && route.credentials.is_none()
                    && attempt.covers(ProxyAuthorizationAttempt::Preemptive)
                {
                    // A caller's own field on a route without configured
                    // credentials goes where a first attempt carries them.
                    place(name, &mut expanded);
                }
            }
            RequestField::Caller { name, .. } => {
                place(name, &mut expanded);
            }
            RequestField::ClientHint { name } if !is_managed(managed, name) => {
                place(name, &mut expanded);
            }
            RequestField::ClientHints => {
                for hint in hints.map_or(&[][..], ClientHintSettings::hints) {
                    if !slotted.contains(&hint.name()) && !is_managed(managed, hint.name()) {
                        place(hint.name(), &mut expanded);
                    }
                }
            }
            _ => {}
        }
    }
    expanded.extend(
        caller
            .iter()
            .zip(used)
            .filter(|(_, used)| !used)
            .map(|(header, _)| header.clone()),
    );
    let placed = route.credentials.is_some() && credentials.is_none();
    (expanded, placed)
}

/// Whether the actual URL and route would insert a managed field absent from the caller.
pub(crate) fn supplies_managed_default(
    fields: &[RequestField],
    caller: &[RequestHeader],
    managed: &[&str],
    (trustworthy, forwarded): (bool, bool),
) -> bool {
    fields.iter().any(|field| {
        let Some(name) = field.name().filter(|name| is_managed(managed, name)) else {
            return false;
        };
        if caller
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case(name))
        {
            return false;
        }
        match field {
            RequestField::ByForwarding {
                unforwarded,
                forwarded: value,
                ..
            } => {
                if forwarded {
                    value.is_some()
                } else {
                    unforwarded.is_some()
                }
            }
            _ => field
                .default_value(if trustworthy {
                    phantom_profile::UrlTrust::PotentiallyTrustworthy
                } else {
                    phantom_profile::UrlTrust::Untrustworthy
                })
                .is_some(),
        }
    })
}

pub(crate) fn is_managed(managed: &[&str], name: &str) -> bool {
    managed
        .iter()
        .any(|managed| managed.eq_ignore_ascii_case(name))
}

fn respelled(name: &str, header: &RequestHeader) -> RequestHeader {
    let field = RequestHeader::new(name, header.value());
    if header.is_sensitive() {
        field.sensitive()
    } else {
        field
    }
}

/// Protocols a request may be sent on, before any attempt.
#[derive(Clone, Copy)]
pub(crate) struct ProtocolScope {
    /// The exact protocol, or `None` for an ALPN-negotiated H1 or H2 request.
    pub(crate) exact: Option<HttpProtocol>,
    /// Whether a negotiated request may move to HTTP/3 through Alt-Svc: the
    /// client stores alternatives and the route can carry QUIC.
    pub(crate) alt_svc: bool,
    /// Whether the response will be decoded from `Accept-Encoding`.
    pub(crate) content_decoding: bool,
}

/// Fills a declared caller slot, or validates a header explicitly placed by
/// the caller. No content type is appended without declared placement.
pub(crate) fn place_prepared_content_type(
    prepared: Option<&PreparedRequestTemplate>,
    scope: ProtocolScope,
    http2_fallback: bool,
    caller: &mut Vec<RequestHeader>,
    content_type: &str,
) -> Result<bool, RequestError> {
    let mut existing = caller
        .iter()
        .filter(|header| header.name().eq_ignore_ascii_case("content-type"));
    if let Some(first) = existing.next() {
        if existing.next().is_some() || first.value() != content_type.as_bytes() {
            return Err(RequestError::prepared_body_content_type(
                "prepared body needs one matching Content-Type field",
            ));
        }
        return Ok(false);
    }
    let Some(prepared) = prepared else {
        return Err(RequestError::prepared_body_content_type(
            "prepared body needs a Content-Type caller slot or explicit field",
        ));
    };
    if !caller_slot_is_declared(prepared, scope, http2_fallback, "content-type") {
        return Err(RequestError::prepared_body_content_type(
            "prepared body needs a Content-Type caller slot on every selected protocol",
        ));
    }
    caller.push(RequestHeader::new("content-type", content_type));
    Ok(true)
}

fn selected_protocols(
    scope: ProtocolScope,
    http2_fallback: bool,
) -> impl Iterator<Item = HttpProtocol> {
    let protocols = match scope.exact {
        Some(protocol) => [
            Some(protocol),
            (protocol == HttpProtocol::Http3 && http2_fallback).then_some(HttpProtocol::Http2),
            None,
        ],
        None => [
            Some(HttpProtocol::Http1),
            Some(HttpProtocol::Http2),
            scope.alt_svc.then_some(HttpProtocol::Http3),
        ],
    };
    protocols.into_iter().flatten()
}

pub(crate) fn place_prepared_content_length(
    prepared: Option<&PreparedRequestTemplate>,
    scope: ProtocolScope,
    http2_fallback: bool,
    caller: &mut Vec<RequestHeader>,
    length: u64,
) -> Result<bool, RequestError> {
    if caller
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case("content-length"))
    {
        // The transport's shared framing checks validate exactness, canonical
        // spelling, and duplicate values before opening a connection.
        return Ok(false);
    }
    let Some(prepared) = prepared else {
        return Ok(false);
    };
    let any_slot = selected_protocols(scope, http2_fallback).any(|protocol| {
        prepared.fields_for(protocol).is_some_and(|fields| fields.iter().any(|field| {
            matches!(field, RequestField::Caller { name, .. } if name.eq_ignore_ascii_case("content-length"))
        }))
    });
    if !any_slot {
        return Ok(false);
    }
    if !caller_slot_is_declared(prepared, scope, http2_fallback, "content-length") {
        return Err(RequestError::prepared_body_content_type(
            "prepared body needs a Content-Length caller slot on every selected protocol",
        ));
    }
    caller.push(RequestHeader::new("content-length", length.to_string()));
    Ok(true)
}

pub(crate) fn caller_slot_is_declared(
    prepared: &PreparedRequestTemplate,
    scope: ProtocolScope,
    http2_fallback: bool,
    name: &str,
) -> bool {
    selected_protocols(scope, http2_fallback).all(|protocol| prepared.fields_for(protocol).is_some_and(|fields| fields.iter().any(|field| {
        matches!(field, RequestField::Caller { name: declared, .. } if declared.eq_ignore_ascii_case(name))
    })))
}

/// Names eligible for the preparatory hook on every selected protocol.
pub(crate) fn caller_slots(
    prepared: &PreparedRequestTemplate,
    scope: ProtocolScope,
    http2_fallback: bool,
) -> Vec<Box<str>> {
    let Some(first) = selected_protocols(scope, http2_fallback)
        .next()
        .and_then(|protocol| prepared.fields_for(protocol))
    else {
        return Vec::new();
    };
    first
        .iter()
        .filter_map(|field| match field {
            RequestField::Caller { name, .. }
                if caller_slot_is_declared(prepared, scope, http2_fallback, name) =>
            {
                Some(name.clone())
            }
            _ => None,
        })
        .collect()
}

/// Revalidates provenance without recreating stripped fields on redirects.
pub(crate) fn check_filled_slots(
    prepared: Option<&PreparedRequestTemplate>,
    scope: ProtocolScope,
    http2_fallback: bool,
    caller: &[RequestHeader],
    filled: &[Box<str>],
) -> Result<(), RequestError> {
    let invalid = filled.iter().any(|name| {
        caller
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case(name))
            && prepared.is_none_or(|prepared| {
                !caller_slot_is_declared(prepared, scope, http2_fallback, name)
            })
    });
    if invalid {
        return Err(RequestError::request_template_filled_slot());
    }
    Ok(())
}

/// Checks the prepared template against the request before any I/O.
///
/// # Errors
///
/// Returns a request-template error for a protocol the template has no
/// field order for, `Accept-Encoding` values that differ between protocol
/// lists when the response will be decoded, a required caller slot the
/// caller leaves empty, profile hints sent by default when the template has no client-hint slot, or a
/// caller field carrying a hint the profile sends only on request when the
/// template does not capture where such hints go.
#[cfg(test)]
pub(crate) fn check(
    prepared: &PreparedRequestTemplate,
    scope: ProtocolScope,
    http2_fallback: bool,
    caller: &[RequestHeader],
    hints: Option<&ClientHintSettings>,
    forwarded: bool,
) -> Result<(), RequestError> {
    check_with_managed_headers(
        prepared,
        scope,
        http2_fallback,
        caller,
        hints,
        &[],
        (false, forwarded),
    )
}

pub(crate) fn check_with_managed_headers(
    prepared: &PreparedRequestTemplate,
    scope: ProtocolScope,
    http2_fallback: bool,
    caller: &[RequestHeader],
    hints: Option<&ClientHintSettings>,
    managed: &[&str],
    conditions: (bool, bool),
) -> Result<(), RequestError> {
    let template = &prepared.0.template;
    if selected_protocols(scope, http2_fallback).any(|protocol| {
        prepared
            .fields_for(protocol)
            .is_some_and(|fields| supplies_managed_default(fields, caller, managed, conditions))
    }) {
        return Err(RequestError::request_template_managed_default());
    }
    let missing_http3 = template.http3_fields.is_none()
        && (scope.exact == Some(HttpProtocol::Http3) || (scope.exact.is_none() && scope.alt_svc));
    if missing_http3 {
        return Err(RequestError::request_template_protocol());
    }
    if scope.content_decoding && !prepared.0.accept_encoding_agrees[usize::from(conditions.1)] {
        return Err(RequestError::request_template_accept_encoding());
    }

    let missing_required = selected_protocols(scope, http2_fallback).any(|protocol| {
        prepared.fields_for(protocol).is_some_and(|fields| {
            fields.iter().any(|field| {
                if let RequestField::Caller {
                    name,
                    required: true,
                } = field
                {
                    !caller
                        .iter()
                        .any(|header| header.name().eq_ignore_ascii_case(name))
                } else {
                    false
                }
            })
        })
    });
    if missing_required {
        return Err(RequestError::request_template_required_field());
    }
    // A caller hint is sent even where automatic hints are not, such as to
    // an origin that is not potentially trustworthy, so it is refused here
    // rather than only when the profile's hints are prepared.
    let requested_by_caller = hints.is_some_and(|settings| {
        caller.iter().any(|header| {
            settings.hints().iter().any(|hint| {
                hint.delivery() != ClientHintDelivery::Default
                    && !is_managed(managed, hint.name())
                    && hint.name().eq_ignore_ascii_case(header.name())
            })
        })
    });
    if !template.requested_client_hint_placement && requested_by_caller {
        return Err(RequestError::request_template_requested_hint());
    }
    // Without a slot, automatic hints would go before every template field,
    // a position no capture shows. A Firefox template has none.
    let has_hint_slot = !prepared.0.client_hint_slots.is_empty();
    let sends_default_hints = hints.is_some_and(|settings| {
        settings.hints().iter().any(|hint| {
            hint.delivery() == ClientHintDelivery::Default && !is_managed(managed, hint.name())
        })
    });
    if !has_hint_slot && sends_default_hints {
        return Err(RequestError::request_template_unslotted_hints());
    }
    Ok(())
}

/// Returns every protocol list the template has.
fn lists(template: &RequestTemplate) -> impl Iterator<Item = &[RequestField]> {
    [
        Some(&template.http1_fields[..]),
        Some(&template.http2_fields[..]),
        template.http3_fields.as_deref(),
    ]
    .into_iter()
    .flatten()
}

/// Returns the value the first entry named `name` sends to a URL of this
/// trust when the caller supplies no such field.
fn default_value<'a>(fields: &'a [RequestField], name: &str, trustworthy: bool) -> Option<&'a str> {
    default_value_on_route(fields, name, trustworthy, false)
}

fn default_value_on_route<'a>(
    fields: &'a [RequestField],
    name: &str,
    trustworthy: bool,
    forwarded: bool,
) -> Option<&'a str> {
    fields
        .iter()
        .find(|field| {
            field
                .name()
                .is_some_and(|field_name| field_name.eq_ignore_ascii_case(name))
        })
        .and_then(|field| match field {
            RequestField::ByForwarding {
                unforwarded,
                forwarded: value,
                ..
            } => {
                if forwarded {
                    value.as_deref()
                } else {
                    unforwarded.as_deref()
                }
            }
            _ => field.default_value(if trustworthy {
                phantom_profile::UrlTrust::PotentiallyTrustworthy
            } else {
                phantom_profile::UrlTrust::Untrustworthy
            }),
        })
}

#[cfg(test)]
#[path = "template/tests.rs"]
mod tests;
