//! Expansion and checks for browser request templates.

use phantom_net::request::RequestHeader;
use phantom_profile::{ClientHintDelivery, ClientHintSettings, RequestField, RequestTemplate};

use crate::{HttpProtocol, RequestError};

/// Returns the template's field list for `protocol`, if one was captured.
pub(crate) fn fields_for(
    template: &RequestTemplate,
    protocol: HttpProtocol,
) -> Option<&[RequestField]> {
    match protocol {
        HttpProtocol::Http1 => Some(&template.http1_fields),
        HttpProtocol::Http2 => Some(&template.http2_fields),
        HttpProtocol::Http3 => template.http3_fields.as_deref(),
    }
}

/// Emits the template's fields in order with the caller's fields in place.
///
/// A caller field whose name matches a literal, caller, or client-hint slot
/// takes that slot's position and spelling, keeping its value and
/// sensitivity; a literal with no caller field emits its captured value.
/// Caller fields for profile client hints fill the client-hints slot in
/// profile order. Automatic client hints are added later, once the
/// connection is chosen. Every other caller field follows the template in
/// the caller's order.
pub(crate) fn expand(
    fields: &[RequestField],
    caller: &[RequestHeader],
    hints: Option<&ClientHintSettings>,
) -> Vec<RequestHeader> {
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
            RequestField::Literal { name, value } => {
                if !place(name, &mut expanded) {
                    expanded.push(RequestHeader::new(&**name, value.as_bytes()));
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
    expanded
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
    /// Whether a negotiated request may move to HTTP/3 through Alt-Svc.
    pub(crate) alt_svc: bool,
    /// Whether the response will be decoded from `Accept-Encoding`.
    pub(crate) content_decoding: bool,
}

/// Validates the template against the request before any I/O.
///
/// # Errors
///
/// Returns a request-template error for invalid template data, a protocol
/// the template has no field order for, a required caller slot the caller
/// leaves empty, profile hints sent by default when the template has no
/// client-hint slot, or a caller field carrying a hint the profile sends only
/// on request when the template does not capture where such hints go.
pub(crate) fn check(
    template: &RequestTemplate,
    scope: ProtocolScope,
    caller: &[RequestHeader],
    hints: Option<&ClientHintSettings>,
) -> Result<(), RequestError> {
    template
        .validate()
        .map_err(RequestError::invalid_request_template)?;
    let missing_http3 = template.http3_fields.is_none()
        && (scope.exact == Some(HttpProtocol::Http3) || (scope.exact.is_none() && scope.alt_svc));
    if missing_http3 {
        return Err(RequestError::request_template_protocol());
    }
    if scope.content_decoding {
        let mut codings = lists(template).map(|fields| literal(fields, "accept-encoding"));
        let first = codings.next().flatten();
        if codings.any(|coding| coding != first) {
            return Err(RequestError::request_template_accept_encoding());
        }
    }

    let missing_required = lists(template).flatten().any(|field| {
        matches!(field, RequestField::Caller { name, required: true }
            if !caller.iter().any(|header| header.name().eq_ignore_ascii_case(name)))
    });
    if missing_required {
        return Err(RequestError::request_template_required_field());
    }
    // A caller hint is sent even where automatic hints are not, such as to
    // an `http://` origin, so it is refused here rather than only when the
    // profile's hints are prepared.
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
    let has_hint_slot = lists(template).any(|fields| {
        fields.iter().any(|field| {
            matches!(
                field,
                RequestField::ClientHint { .. } | RequestField::ClientHints
            )
        })
    });
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

/// Returns the template's literal `Accept-Encoding`, for decoding decisions
/// made before the protocol is chosen.
pub(crate) fn accept_encoding(template: &RequestTemplate) -> Option<&str> {
    literal(&template.http1_fields, "accept-encoding")
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

fn literal<'a>(fields: &'a [RequestField], name: &str) -> Option<&'a str> {
    fields.iter().find_map(|field| match field {
        RequestField::Literal {
            name: field_name,
            value,
        } if field_name.eq_ignore_ascii_case(name) => Some(&**value),
        _ => None,
    })
}

#[cfg(test)]
#[path = "template/tests.rs"]
mod tests;
