//! Ordered request fields for ordinary browser requests.
//!
//! A [`RequestTemplate`] records the fields one browser sends for one kind of
//! request, such as a top-level navigation, in the exact order observed for
//! each protocol. Values that describe the page or persona, such as `Referer`,
//! are caller slots; client hints are slots filled from the profile's
//! [`ClientHintSettings`](crate::ClientHintSettings).

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
    /// The position of a caller-supplied field; emits nothing when the caller
    /// supplies no field with this name.
    Caller {
        /// Exact field-name spelling emitted with the caller's value.
        name: Box<str>,
    },
    /// The position of one client hint when it is sent.
    ClientHint {
        /// Lowercase client-hint field name.
        name: Box<str>,
    },
    /// The position of every sent client hint without its own
    /// [`Self::ClientHint`] slot, in profile order.
    ClientHints,
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

    /// Creates a caller-supplied field slot.
    #[must_use]
    pub fn caller(name: impl Into<Box<str>>) -> Self {
        Self::Caller { name: name.into() }
    }

    /// Creates the position of one client hint.
    #[must_use]
    pub fn client_hint(name: impl Into<Box<str>>) -> Self {
        Self::ClientHint { name: name.into() }
    }

    /// Returns the field name of a literal, caller, or single-hint slot.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Literal { name, .. } | Self::Caller { name } | Self::ClientHint { name } => {
                Some(name)
            }
            Self::ClientHints => None,
        }
    }

    const fn is_hint_slot(&self) -> bool {
        matches!(self, Self::ClientHint { .. } | Self::ClientHints)
    }
}

/// A product token and major version, such as `Chrome/153`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductVersion {
    /// Product name, compared exactly.
    pub name: Box<str>,
    /// Major version: the leading integer of the version text.
    pub major: u32,
}

impl ProductVersion {
    /// Creates a product token and major version.
    #[must_use]
    pub fn new(name: impl Into<Box<str>>, major: u32) -> Self {
        Self {
            name: name.into(),
            major,
        }
    }
}

/// Browser family and version a template's request claims.
///
/// A client uses this to reject a `User-Agent` or `sec-ch-ua` value that
/// names another browser or version than the template it is sent with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestIdentity {
    /// `User-Agent` product tokens that must be present with these major
    /// versions, such as `Chrome/153`.
    ///
    /// When this is nonempty, a request must carry a `User-Agent`: either
    /// every protocol list has a literal one, or the caller supplies it.
    pub user_agent_products: Vec<ProductVersion>,
    /// `User-Agent` product-token names that must be absent, such as `Edg`
    /// for Chrome or `Chrome` for Firefox.
    pub excluded_user_agent_products: Vec<Box<str>>,
    /// Brands that `sec-ch-ua` and `sec-ch-ua-full-version-list` must list
    /// with these major versions.
    ///
    /// A client rejects a list that repeats one of these brands or names any
    /// other brand than the one GREASE brand Chromium derives from their
    /// shared major version, such as `"Not_A Brand";v="8"` for 153.
    ///
    /// `None` means the browser sends no user-agent client hints, so any
    /// such field contradicts the template.
    pub client_hint_brands: Option<Vec<ProductVersion>>,
}

/// Ordered fields for one kind of ordinary browser request.
///
/// Each protocol has its own list because browsers order and spell fields
/// differently on HTTP/1.1, HTTP/2, and HTTP/3. `Host`, pseudo-header fields,
/// cookies, and body framing fields are not template data: the client
/// generates them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestTemplate {
    /// Browser identity that caller identity fields must agree with.
    pub identity: RequestIdentity,
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
        validate_identity(&self.identity)
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
                if !value
                    .bytes()
                    .all(|byte| matches!(byte, b'\t' | b' '..=b'~'))
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

/// Returns whether `field`, named `lower`, is forbidden on HTTP/2 and HTTP/3.
fn is_connection_specific(field: &RequestField, lower: &str) -> bool {
    if lower == "te" {
        return !matches!(field, RequestField::Literal { value, .. } if &**value == "trailers");
    }
    CONNECTION_SPECIFIC.contains(&lower)
}

fn validate_identity(identity: &RequestIdentity) -> Result<(), InvalidRequestTemplate> {
    let names = identity
        .user_agent_products
        .iter()
        .map(|product| &product.name)
        .chain(&identity.excluded_user_agent_products)
        .chain(
            identity
                .client_hint_brands
                .iter()
                .flatten()
                .map(|b| &b.name),
        );
    for name in names {
        if name.is_empty() || name.bytes().any(|byte| !matches!(byte, b' '..=b'~')) {
            return Err(InvalidRequestTemplate::new(
                "identity",
                "product and brand names must be non-empty visible ASCII",
            ));
        }
    }
    if identity.user_agent_products.iter().any(|product| {
        identity
            .excluded_user_agent_products
            .iter()
            .any(|excluded| excluded == &product.name)
    }) {
        return Err(InvalidRequestTemplate::new(
            "identity",
            "a User-Agent product cannot be both required and excluded",
        ));
    }
    Ok(())
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
