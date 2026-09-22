//! Expansion and identity checks for browser request templates.

use phantom_net::request::RequestHeader;
use phantom_profile::{
    ClientHintDelivery, ClientHintSettings, ProductVersion, RequestField, RequestIdentity,
    RequestTemplate,
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
/// Returns a request-template error for invalid template data, a protocol
/// the template has no field order for, profile hints sent by default when
/// the template has no client-hint slot, or a caller field carrying a hint
/// the profile sends only on request when the template does not capture
/// where such hints go; and an identity-mismatch error when
/// a caller `User-Agent`, a caller brand-list client hint, or the profile's
/// brand-list client hint contradicts the template's identity, or when the
/// identity requires `User-Agent` products and no `User-Agent` would be sent.
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

    let identity = &template.identity;
    let caller_user_agent = caller
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case("user-agent"));
    let template_user_agent = lists(template).all(|fields| literal(fields, "user-agent").is_some());
    if !identity.user_agent_products.is_empty() && !caller_user_agent && !template_user_agent {
        return Err(RequestError::identity_mismatch(
            "the request template requires a User-Agent, and neither it nor the caller supplies one",
        ));
    }
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
///
/// The list must name every required brand exactly once with its major
/// version, and nothing else except at most once the GREASE brand Chromium
/// derives from that major version, so a list that adds another browser's
/// brand, or another version's GREASE brand, is rejected.
fn brands_agree(identity: &RequestIdentity, value: &[u8]) -> bool {
    let Some(required) = &identity.client_hint_brands else {
        return false;
    };
    let grease_brand = shared_major(required).map(grease_brand);
    let Ok(text) = std::str::from_utf8(value) else {
        return false;
    };
    let Ok(list) = Parser::new(text).parse::<sfv::List>() else {
        return false;
    };
    let mut seen = vec![false; required.len()];
    let mut grease = false;
    for entry in &list {
        let ListEntry::Item(item) = entry else {
            return false;
        };
        let BareItem::String(brand) = &item.bare_item else {
            return false;
        };
        let version = item
            .params
            .iter()
            .find_map(|(key, value)| match value {
                BareItem::String(version) if key.as_str() == "v" => Some(version.as_str()),
                _ => None,
            })
            .and_then(major);
        let brand = brand.as_str();
        if let Some(index) = required.iter().position(|product| *product.name == *brand) {
            if seen[index] || version != Some(required[index].major) {
                return false;
            }
            seen[index] = true;
        } else if !grease
            && grease_brand
                .as_ref()
                .is_some_and(|(name, major)| name == brand && version == Some(*major))
        {
            grease = true;
        } else {
            return false;
        }
    }
    seen.into_iter().all(|seen| seen)
}

/// Characters Chromium's GREASE brand algorithm places around the `A`.
///
/// `GetGreasedUserAgentBrandVersion` in Chromium's
/// `components/embedder_support/user_agent_utils.cc` builds the brand as
/// `"Not" + c[seed % 11] + "A" + c[(seed + 1) % 11] + "Brand"` over these
/// characters, with the version `["8", "99", "24"][seed % 3]`; the seed is the
/// browser's major version. See also the UA-CH specification's "create
/// arbitrary brands" algorithm.
const GREASE_BRAND_CHARACTERS: &[u8; 11] = b" (:-./);=?_";
/// Versions Chromium's GREASE brand algorithm chooses from.
const GREASE_BRAND_MAJORS: [u32; 3] = [8, 99, 24];

/// Returns the one GREASE brand and major version Chromium sends for major
/// version `seed`, such as `("Not_A Brand", 8)` for 153.
fn grease_brand(seed: u32) -> (String, u32) {
    let character = |offset: u32| {
        let index = (seed % 11 + offset) % 11;
        char::from(GREASE_BRAND_CHARACTERS[index as usize])
    };
    let major = GREASE_BRAND_MAJORS[(seed % 3) as usize];
    (format!("Not{}A{}Brand", character(0), character(1)), major)
}

/// Returns the major version every required brand carries, which seeds
/// Chromium's GREASE brand; `None` when they disagree or there are none.
fn shared_major(required: &[ProductVersion]) -> Option<u32> {
    let (first, rest) = required.split_first()?;
    rest.iter()
        .all(|product| product.major == first.major)
        .then_some(first.major)
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
