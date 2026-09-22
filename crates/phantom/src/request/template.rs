//! Expansion and identity checks for browser request templates.

use phantom_net::request::RequestHeader;
use phantom_profile::{
    ClientHintSettings, ProductVersion, RequestField, RequestIdentity, RequestTemplate,
};
use sfv::{BareItem, ListEntry, Parser};

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
            RequestField::Caller { name } | RequestField::ClientHint { name } => {
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

/// Validates the template and the request's identity fields before any I/O.
///
/// # Errors
///
/// Returns a request-template error for invalid template data or a protocol
/// the template has no field order for, and an identity-mismatch error when
/// a caller `User-Agent`, a caller brand-list client hint, or the profile's
/// brand-list client hint contradicts the template's identity.
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
        let mut codings = [
            Some(&template.http1_fields[..]),
            Some(&template.http2_fields[..]),
            template.http3_fields.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(|fields| literal(fields, "accept-encoding"));
        let first = codings.next().flatten();
        if codings.any(|coding| coding != first) {
            return Err(RequestError::request_template_accept_encoding());
        }
    }

    let identity = &template.identity;
    for header in caller {
        let name = header.name();
        if name.eq_ignore_ascii_case("user-agent") && !user_agent_agrees(identity, header.value()) {
            return Err(RequestError::identity_mismatch(
                "User-Agent names another browser or version than the request template",
            ));
        }
        if is_brand_list(name) && !brands_agree(identity, header.value()) {
            return Err(RequestError::identity_mismatch(
                "a brand-list client hint names another browser or version than the request template",
            ));
        }
    }
    let profile_brands = hints
        .into_iter()
        .flat_map(ClientHintSettings::hints)
        .filter(|hint| is_brand_list(hint.name()));
    for hint in profile_brands {
        if !brands_agree(identity, hint.value()) {
            return Err(RequestError::identity_mismatch(
                "the profile's client hints name another browser or version than the request template",
            ));
        }
    }
    Ok(())
}

/// Returns the template's literal `Accept-Encoding`, for decoding decisions
/// made before the protocol is chosen.
pub(crate) fn accept_encoding(template: &RequestTemplate) -> Option<&str> {
    literal(&template.http1_fields, "accept-encoding")
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

fn is_brand_list(name: &str) -> bool {
    name.eq_ignore_ascii_case("sec-ch-ua")
        || name.eq_ignore_ascii_case("sec-ch-ua-full-version-list")
}

/// Checks `User-Agent` product tokens; parenthesized comments are skipped.
fn user_agent_agrees(identity: &RequestIdentity, value: &[u8]) -> bool {
    let Ok(value) = std::str::from_utf8(value) else {
        return false;
    };
    let products = user_agent_products(value);
    let required = identity.user_agent_products.iter().all(|required| {
        products.iter().any(|(name, version)| {
            *name == &*required.name && major(version) == Some(required.major)
        })
    });
    let excluded = products.iter().any(|(name, _)| {
        identity
            .excluded_user_agent_products
            .iter()
            .any(|excluded| &**excluded == *name)
    });
    required && !excluded
}

fn user_agent_products(value: &str) -> Vec<(&str, &str)> {
    let mut products = Vec::new();
    let mut depth = 0_usize;
    let mut start = None;
    for (index, character) in value.char_indices().chain([(value.len(), ' ')]) {
        match character {
            '(' => {
                depth += 1;
                start = None;
            }
            ')' => depth = depth.saturating_sub(1),
            ' ' | '\t' if depth == 0 => {
                if let Some(token) = start.take().map(|start| &value[start..index]) {
                    let (name, version) = token.split_once('/').unwrap_or((token, ""));
                    products.push((name, version));
                }
            }
            _ if depth == 0 && start.is_none() => start = Some(index),
            _ => {}
        }
    }
    products
}

/// Checks a `sec-ch-ua`-style structured-field list of branded versions.
fn brands_agree(identity: &RequestIdentity, value: &[u8]) -> bool {
    let Some(required) = &identity.client_hint_brands else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(value) else {
        return false;
    };
    let Ok(list) = Parser::new(text).parse::<sfv::List>() else {
        return false;
    };
    let mut brands = Vec::with_capacity(list.len());
    for entry in &list {
        let ListEntry::Item(item) = entry else {
            return false;
        };
        let BareItem::String(brand) = &item.bare_item else {
            return false;
        };
        let version = item.params.iter().find_map(|(key, value)| match value {
            BareItem::String(version) if key.as_str() == "v" => Some(version.as_str()),
            _ => None,
        });
        brands.push((brand.as_str(), version.and_then(major)));
    }
    required.iter().all(|ProductVersion { name, major }| {
        brands
            .iter()
            .any(|(brand, version)| *brand == &**name && *version == Some(*major))
    })
}

fn major(version: &str) -> Option<u32> {
    let digits = version
        .split(|character: char| !character.is_ascii_digit())
        .next()?;
    digits.parse().ok()
}

#[cfg(test)]
#[path = "template/tests.rs"]
mod tests;
