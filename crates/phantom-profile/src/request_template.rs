//! Ordered request fields for ordinary browser requests.
//!
//! A [`RequestTemplate`] records the fields one browser sends for one kind of
//! request, such as a top-level navigation, in the exact order observed for
//! each protocol. Values that describe the page or persona, such as `Referer`,
//! are caller slots; client hints are slots filled from the profile's
//! [`ClientHintSettings`](crate::ClientHintSettings). Fields whose value
//! depends on whether the request URL is potentially trustworthy, such as
//! `Accept-Encoding` and the `Sec-Fetch-*` fields, are
//! [`RequestField::ByTrust`] entries. Fields whose presence depends on whether
//! an HTTP proxy forwards the request, such as Chromium's `Proxy-Connection`,
//! are [`RequestField::ByForwarding`] entries.

use std::{collections::HashSet, error::Error, fmt};

use crate::http2::Http2Priority;

/// One field, caller slot, or client-hint position in a request template.
///
/// Field-name spelling is emitted exactly as written. HTTP/2 and HTTP/3
/// templates must use lowercase names.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestField {
    /// A field emitted with this name and value unless the caller supplies a
    /// field with the same name, whose value then takes this position.
    Literal {
        /// Exact field-name spelling.
        name: Box<str>,
        /// Captured field value.
        value: Box<str>,
    },
    /// The position of a caller-supplied field.
    ///
    /// An optional slot emits nothing when the caller supplies no field with
    /// this name. A client refuses to send a request that leaves a required
    /// slot empty.
    Caller {
        /// Exact field-name spelling emitted with the caller's value.
        name: Box<str>,
        /// Whether a request with this template must supply the field.
        required: bool,
    },
    /// The position of one client hint when it is sent.
    ClientHint {
        /// Lowercase client-hint field name.
        name: Box<str>,
    },
    /// The position of every sent client hint without its own
    /// [`Self::ClientHint`] slot, in profile order.
    ClientHints,
    /// A field whose captured value depends on whether the request URL is
    /// potentially trustworthy, as W3C Secure Contexts defines it.
    ///
    /// A URL is potentially trustworthy when its scheme is `https`, or its
    /// host is a loopback address (`127.0.0.0/8` or `::1`), `localhost`, or a
    /// name under `.localhost`. Browsers send some fields only to such URLs,
    /// and some with another value. A caller field with this name takes this
    /// position in either case, as it does for [`Self::Literal`].
    ByTrust {
        /// Exact field-name spelling.
        name: Box<str>,
        /// Value sent to a potentially trustworthy URL, or `None` to send
        /// nothing there.
        trustworthy: Option<Box<str>>,
        /// Value sent to any other URL, or `None` to send nothing there.
        untrustworthy: Option<Box<str>>,
    },
    /// A field whose captured value depends on whether an HTTP proxy
    /// forwards the request.
    ///
    /// A request is forwarded when an HTTP proxy route carries an `http://`
    /// request itself: in absolute form on HTTP/1.1, or with `:scheme` `http`
    /// on an HTTP/2 proxy connection. A request inside a CONNECT or SOCKS5
    /// tunnel, or on a direct route, is not forwarded. Chromium sends
    /// `Proxy-Connection: keep-alive` in place of `Connection: keep-alive` on
    /// a forwarded HTTP/1.1 request. A caller field with this name takes this
    /// position in either case, as it does for [`Self::Literal`].
    ByForwarding {
        /// Exact field-name spelling.
        name: Box<str>,
        /// Value sent when the request is not forwarded, or `None` to send
        /// nothing then.
        unforwarded: Option<Box<str>>,
        /// Value sent when an HTTP proxy forwards the request, or `None` to
        /// send nothing then.
        forwarded: Option<Box<str>>,
    },
}

impl RequestField {
    /// Creates a field with a captured default value.
    #[must_use]
    pub fn literal(name: impl Into<Box<str>>, value: impl Into<Box<str>>) -> Self {
        Self::Literal {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Creates an optional caller-supplied field slot.
    #[must_use]
    pub fn caller(name: impl Into<Box<str>>) -> Self {
        Self::Caller {
            name: name.into(),
            required: false,
        }
    }

    /// Creates a caller-supplied field slot that every request must fill.
    #[must_use]
    pub fn required_caller(name: impl Into<Box<str>>) -> Self {
        Self::Caller {
            name: name.into(),
            required: true,
        }
    }

    /// Creates the position of one client hint.
    #[must_use]
    pub fn client_hint(name: impl Into<Box<str>>) -> Self {
        Self::ClientHint { name: name.into() }
    }

    /// Creates a field sent only to a potentially trustworthy URL.
    #[must_use]
    pub fn trustworthy_only(name: impl Into<Box<str>>, value: impl Into<Box<str>>) -> Self {
        Self::ByTrust {
            name: name.into(),
            trustworthy: Some(value.into()),
            untrustworthy: None,
        }
    }

    /// Creates a field with one value for a potentially trustworthy URL and
    /// another for any other URL.
    #[must_use]
    pub fn by_trust(
        name: impl Into<Box<str>>,
        trustworthy: impl Into<Box<str>>,
        untrustworthy: impl Into<Box<str>>,
    ) -> Self {
        Self::ByTrust {
            name: name.into(),
            trustworthy: Some(trustworthy.into()),
            untrustworthy: Some(untrustworthy.into()),
        }
    }

    /// Creates a field sent only when an HTTP proxy does not forward the
    /// request.
    #[must_use]
    pub fn unless_forwarded(name: impl Into<Box<str>>, value: impl Into<Box<str>>) -> Self {
        Self::ByForwarding {
            name: name.into(),
            unforwarded: Some(value.into()),
            forwarded: None,
        }
    }

    /// Creates a field sent only when an HTTP proxy forwards the request.
    #[must_use]
    pub fn when_forwarded(name: impl Into<Box<str>>, value: impl Into<Box<str>>) -> Self {
        Self::ByForwarding {
            name: name.into(),
            unforwarded: None,
            forwarded: Some(value.into()),
        }
    }

    /// Returns the field name of a literal, caller, single-hint,
    /// trust-dependent, or forwarding-dependent entry.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Literal { name, .. }
            | Self::Caller { name, .. }
            | Self::ClientHint { name }
            | Self::ByTrust { name, .. }
            | Self::ByForwarding { name, .. } => Some(name),
            Self::ClientHints => None,
        }
    }

    /// Returns the value this entry sends when the caller supplies no field
    /// of its name and no HTTP proxy forwards the request: a literal's value,
    /// a trust-dependent entry's value for `trustworthy`, or a
    /// forwarding-dependent entry's unforwarded value. Slots return `None`.
    #[must_use]
    pub fn default_value(&self, trustworthy: bool) -> Option<&str> {
        match self {
            Self::Literal { value, .. } => Some(value),
            Self::ByTrust {
                trustworthy: secure,
                untrustworthy: other,
                ..
            } => if trustworthy { secure } else { other }.as_deref(),
            Self::ByForwarding { unforwarded, .. } => unforwarded.as_deref(),
            Self::Caller { .. } | Self::ClientHint { .. } | Self::ClientHints => None,
        }
    }

    const fn is_hint_slot(&self) -> bool {
        matches!(self, Self::ClientHint { .. } | Self::ClientHints)
    }
}

/// Ordered fields for one kind of ordinary browser request.
///
/// Each protocol has its own list because browsers order and spell fields
/// differently on HTTP/1.1, HTTP/2, and HTTP/3. `Host`, pseudo-header fields,
/// cookies, and body framing fields are not template data: the client
/// generates them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestTemplate {
    /// Ordered HTTP/1.1 fields after `Host`.
    pub http1_fields: Vec<RequestField>,
    /// Ordered ordinary HTTP/2 fields after the pseudo-header fields.
    pub http2_fields: Vec<RequestField>,
    /// Ordered ordinary HTTP/3 fields after the pseudo-header fields, or
    /// `None` when no HTTP/3 capture backs this request kind.
    pub http3_fields: Option<Vec<RequestField>>,
    /// HTTP/2 HEADERS priority of this request kind, or `None` to keep the
    /// connection's
    /// [`Http2Settings::headers_priority`](crate::Http2Settings::headers_priority).
    ///
    /// Browsers weight a stream by request kind, so a captured value replaces
    /// the connection's priority for this template's requests only. It must
    /// depend on stream 0, because a request's own stream ID is not known
    /// before it is sent.
    pub http2_priority: Option<Http2Priority>,
    /// Whether a capture shows where this request kind places client hints
    /// that an origin requested through `Accept-CH`.
    ///
    /// A capture on one protocol suffices: the built-in navigation templates
    /// rest on an HTTP/1.1 capture, and their HTTP/2 and HTTP/3 placement is
    /// inferred from it.
    ///
    /// When `false`, the template's client-hint slots are backed only for
    /// hints the profile sends by default, and a client must refuse to send a
    /// requested hint with it rather than guess a position.
    pub requested_client_hint_placement: bool,
}

impl RequestTemplate {
    /// Validates field syntax, client-hint placement, and the HTTP/2 priority.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRequestTemplate`] when a list has an invalid or
    /// repeated name, a generated field such as `Host` or `Cookie`, an
    /// uppercase HTTP/2 or HTTP/3 name, a connection-specific field such as
    /// `Connection` in an HTTP/2 or HTTP/3 list, an invalid literal value, a
    /// client-hint slot without a later literal field, when the lists place
    /// client hints differently, or when the HTTP/2 priority depends on a
    /// stream other than 0 or has a weight outside 1..=256.
    pub fn validate(&self) -> Result<(), InvalidRequestTemplate> {
        if let Some(priority) = self.http2_priority {
            if priority.dependency_stream_id != 0 {
                return Err(InvalidRequestTemplate::new(
                    "http2_priority",
                    "a template's HTTP/2 priority must depend on stream 0",
                ));
            }
            if !(1..=256).contains(&priority.weight) {
                return Err(InvalidRequestTemplate::new(
                    "http2_priority",
                    "priority weight must be in 1..=256",
                ));
            }
        }
        validate_fields(&self.http1_fields, "http1_fields", false)?;
        validate_fields(&self.http2_fields, "http2_fields", true)?;
        let placement = client_hint_placement(&self.http2_fields);
        if client_hint_placement(&self.http1_fields) != placement {
            return Err(InvalidRequestTemplate::new(
                "http1_fields",
                "client hints must have the same slots and following fields on every protocol",
            ));
        }
        if let Some(fields) = &self.http3_fields {
            validate_fields(fields, "http3_fields", true)?;
            if client_hint_placement(fields) != placement {
                return Err(InvalidRequestTemplate::new(
                    "http3_fields",
                    "client hints must have the same slots and following fields on every protocol",
                ));
            }
        }
        Ok(())
    }
}

/// One client-hint slot and the fields that follow it up to the first literal.
///
/// The following names are lowercase. Validation guarantees the list is
/// nonempty and ends with a literal field, so the slot's position can be
/// found in any protocol's emitted fields by name.
///
/// This is plumbing between this crate and the `phantom` client, which places
/// automatic client hints with it; it is not part of the supported API.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHintSlot {
    /// The slot's single hint name, or `None` for [`RequestField::ClientHints`].
    pub hint: Option<Box<str>>,
    /// Lowercase names of the following non-hint fields, ending with the
    /// first literal field.
    pub followed_by: Vec<Box<str>>,
}

/// Returns each client-hint slot of `fields` with the fields that follow it.
///
/// A validated template has the same placement on every protocol. Like
/// [`ClientHintSlot`], this is client plumbing, not supported API.
#[doc(hidden)]
#[must_use]
pub fn client_hint_placement(fields: &[RequestField]) -> Vec<ClientHintSlot> {
    fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field.is_hint_slot())
        .map(|(index, field)| {
            let mut followed_by = Vec::new();
            for next in &fields[index + 1..] {
                if next.is_hint_slot() {
                    continue;
                }
                if let Some(name) = next.name() {
                    followed_by.push(name.to_ascii_lowercase().into_boxed_str());
                }
                if matches!(next, RequestField::Literal { .. }) {
                    break;
                }
            }
            ClientHintSlot {
                hint: match field {
                    RequestField::ClientHint { name } => Some(name.clone()),
                    _ => None,
                },
                followed_by,
            }
        })
        .collect()
}

/// Error returned when request-template data is inconsistent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidRequestTemplate {
    field: &'static str,
    message: &'static str,
}

impl InvalidRequestTemplate {
    const fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the reason the setting is invalid.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for InvalidRequestTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid request template {}: {}",
            self.field, self.message
        )
    }
}

impl Error for InvalidRequestTemplate {}

/// Fields the client generates or owns, which a template must not carry.
const GENERATED: [&str; 6] = [
    "host",
    "cookie",
    "content-length",
    "transfer-encoding",
    "trailer",
    "alt-used",
];

/// Connection-specific fields that HTTP/2 and HTTP/3 forbid (RFC 9113
/// section 8.2.2, RFC 9114 section 4.2). `te` is allowed only as a literal
/// `trailers`.
const CONNECTION_SPECIFIC: [&str; 4] = ["connection", "keep-alive", "proxy-connection", "upgrade"];

fn validate_fields(
    fields: &[RequestField],
    field: &'static str,
    lowercase: bool,
) -> Result<(), InvalidRequestTemplate> {
    let mut names = HashSet::with_capacity(fields.len());
    let mut hint_blocks = 0_usize;
    let mut single_hints = 0_usize;
    for (index, template) in fields.iter().enumerate() {
        match template {
            RequestField::ClientHints => hint_blocks += 1,
            RequestField::ClientHint { name } => {
                single_hints += 1;
                if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
                    return Err(InvalidRequestTemplate::new(
                        field,
                        "client-hint slot names must be lowercase",
                    ));
                }
            }
            RequestField::Literal { value, .. } => {
                if !is_field_value(value) {
                    return Err(InvalidRequestTemplate::new(
                        field,
                        "literal values must contain only visible ASCII, spaces, or tabs",
                    ));
                }
            }
            RequestField::ByTrust {
                trustworthy,
                untrustworthy,
                ..
            } => {
                if trustworthy.is_none() && untrustworthy.is_none() {
                    return Err(InvalidRequestTemplate::new(
                        field,
                        "a trust-dependent field needs a value for at least one kind of URL",
                    ));
                }
                if ![trustworthy, untrustworthy]
                    .into_iter()
                    .flatten()
                    .all(|value| is_field_value(value))
                {
                    return Err(InvalidRequestTemplate::new(
                        field,
                        "literal values must contain only visible ASCII, spaces, or tabs",
                    ));
                }
            }
            RequestField::ByForwarding {
                unforwarded,
                forwarded,
                ..
            } => {
                if unforwarded.is_none() && forwarded.is_none() {
                    return Err(InvalidRequestTemplate::new(
                        field,
                        "a forwarding-dependent field needs a value for at least one route",
                    ));
                }
                if ![unforwarded, forwarded]
                    .into_iter()
                    .flatten()
                    .all(|value| is_field_value(value))
                {
                    return Err(InvalidRequestTemplate::new(
                        field,
                        "literal values must contain only visible ASCII, spaces, or tabs",
                    ));
                }
            }
            RequestField::Caller { .. } => {}
        }
        if template.is_hint_slot()
            && !fields[index + 1..]
                .iter()
                .any(|next| matches!(next, RequestField::Literal { .. }))
        {
            return Err(InvalidRequestTemplate::new(
                field,
                "a client-hint slot must be followed by a literal field",
            ));
        }
        let Some(name) = template.name() else {
            continue;
        };
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(InvalidRequestTemplate::new(
                field,
                "field names must be non-empty tokens",
            ));
        }
        if lowercase && name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(InvalidRequestTemplate::new(
                field,
                "HTTP/2 and HTTP/3 field names must be lowercase",
            ));
        }
        let lower = name.to_ascii_lowercase();
        if lowercase && is_connection_specific(template, &lower) {
            return Err(InvalidRequestTemplate::new(
                field,
                "HTTP/2 and HTTP/3 lists must not carry connection-specific fields",
            ));
        }
        if GENERATED.contains(&lower.as_str()) {
            return Err(InvalidRequestTemplate::new(
                field,
                "Host, Cookie, Alt-Used, and body framing fields are generated by the client",
            ));
        }
        if !names.insert(lower) {
            return Err(InvalidRequestTemplate::new(
                field,
                "field names must not repeat",
            ));
        }
    }
    if hint_blocks > 1 || (single_hints > 0 && hint_blocks == 0) {
        return Err(InvalidRequestTemplate::new(
            field,
            "a list has at most one client-hints slot, required when it has single-hint slots",
        ));
    }
    Ok(())
}

fn is_field_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'\t' | b' '..=b'~'))
}

/// Returns whether `field`, named `lower`, is forbidden on HTTP/2 and HTTP/3.
fn is_connection_specific(field: &RequestField, lower: &str) -> bool {
    if lower == "te" {
        return !matches!(field, RequestField::Literal { value, .. } if &**value == "trailers");
    }
    CONNECTION_SPECIFIC.contains(&lower)
}

const fn is_token_byte(byte: u8) -> bool {
    matches!(
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
            | b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
    )
}

#[cfg(test)]
pub(crate) mod capture;
#[cfg(test)]
#[path = "request_template/tests.rs"]
mod tests;
