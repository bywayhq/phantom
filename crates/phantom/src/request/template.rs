//! Expansion and checks for browser request templates.

use std::sync::Arc;

use phantom_net::request::RequestHeader;
use phantom_profile::{
    ClientHintDelivery, ClientHintSettings, Http2Priority, InvalidRequestTemplate,
    ProxyAuthorizationAttempt, RequestField, RequestTemplate,
    request_template::{ClientHintSlot, client_hint_placement},
};

use crate::{HttpProtocol, RequestError};

/// A validated request template that requests share without copying it.
///
/// [`PreparedRequestTemplate::new`] validates the template once. Pass the
/// result to [`RequestBuilder::template`](crate::RequestBuilder::template)
/// for each request; cloning it copies a reference count, not the fields.
#[derive(Clone, Debug)]
pub struct PreparedRequestTemplate(Arc<Prepared>);

#[derive(Debug)]
struct Prepared {
    template: RequestTemplate,
    /// Client-hint placement, the same on every protocol list.
    client_hint_slots: Vec<ClientHintSlot>,
    /// The HTTP/1.1 list's `Accept-Encoding` value for a URL that is not
    /// potentially trustworthy, then for one that is.
    accept_encoding: [Option<Box<str>>; 2],
    /// Whether every protocol list sends the same `Accept-Encoding` value to
    /// both kinds of URL.
    accept_encoding_agrees: bool,
    /// Names of required caller slots on any protocol list.
    required_fields: Vec<Box<str>>,
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
        let client_hint_slots = client_hint_placement(&template.http2_fields);
        let mut accept_encoding: [Option<Box<str>>; 2] = [None, None];
        let mut accept_encoding_agrees = true;
        for trustworthy in [false, true] {
            let mut codings = lists(&template)
                .map(|fields| default_value(fields, "accept-encoding", trustworthy));
            let first = codings.next().flatten();
            accept_encoding_agrees &= codings.all(|coding| coding == first);
            accept_encoding[usize::from(trustworthy)] = first.map(Box::from);
        }
        let mut required_fields: Vec<Box<str>> = Vec::new();
        for field in lists(&template).flatten() {
            if let RequestField::Caller {
                name,
                required: true,
            } = field
                && !required_fields
                    .iter()
                    .any(|seen| seen.eq_ignore_ascii_case(name))
            {
                required_fields.push(name.clone());
            }
        }
        Ok(Self(Arc::new(Prepared {
            template,
            client_hint_slots,
            accept_encoding,
            accept_encoding_agrees,
            required_fields,
        })))
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

    pub(crate) fn requested_client_hint_placement(&self) -> bool {
        self.0.template.requested_client_hint_placement
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
    /// this trust, for decoding decisions made before the protocol is chosen.
    pub(crate) fn accept_encoding(&self, trustworthy: bool) -> Option<&str> {
        self.0.accept_encoding[usize::from(trustworthy)].as_deref()
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
pub(crate) fn expand_on_route(
    fields: &[RequestField],
    caller: &[RequestHeader],
    hints: Option<&ClientHintSettings>,
    trustworthy: bool,
    route: Forwarding<'_>,
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
                    && let Some(value) = field.default_value(trustworthy)
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
            RequestField::Caller { name, .. } | RequestField::ClientHint { name } => {
                place(name, &mut expanded);
            }
            RequestField::ClientHints => {
                for hint in hints.map_or(&[][..], ClientHintSettings::hints) {
                    if !slotted.contains(&hint.name()) {
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
pub(crate) fn check(
    prepared: &PreparedRequestTemplate,
    scope: ProtocolScope,
    caller: &[RequestHeader],
    hints: Option<&ClientHintSettings>,
) -> Result<(), RequestError> {
    let template = &prepared.0.template;
    let missing_http3 = template.http3_fields.is_none()
        && (scope.exact == Some(HttpProtocol::Http3) || (scope.exact.is_none() && scope.alt_svc));
    if missing_http3 {
        return Err(RequestError::request_template_protocol());
    }
    if scope.content_decoding && !prepared.0.accept_encoding_agrees {
        return Err(RequestError::request_template_accept_encoding());
    }

    let missing_required = prepared.0.required_fields.iter().any(|name| {
        !caller
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case(name))
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
        settings
            .hints()
            .iter()
            .any(|hint| hint.delivery() == ClientHintDelivery::Default)
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
    fields
        .iter()
        .find(|field| {
            field
                .name()
                .is_some_and(|field_name| field_name.eq_ignore_ascii_case(name))
        })
        .and_then(|field| field.default_value(trustworthy))
}

#[cfg(test)]
#[path = "template/tests.rs"]
mod tests;
