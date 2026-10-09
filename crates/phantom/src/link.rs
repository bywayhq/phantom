//! Parse Link header values into ordered data.

use std::{error::Error as StdError, fmt, net::Ipv6Addr};

/// Parses the Link header values you supply, in their supplied order.
///
/// Each link keeps its target, parameters, and relation spelling. Quoted
/// values are unescaped. An absent `rel` produces no relations. The first
/// `rel` and `anchor` parameters govern those properties, while all repeated
/// parameters remain available through [`Link::parameters`].
///
/// Targets and anchors are ASCII URI references. Relative references stay
/// relative. Resolve them against the response URL before interpreting a
/// link, including its anchor. A base URL in the response body does not apply.
/// This function does not resolve references or follow links.
///
/// Parameters ending in `*`, including `title*`, retain their encoded bytes.
/// This parser does not decode RFC 8187 values or apply their precedence.
/// Other target attributes remain data without attribute-specific validation.
///
/// `maximum_bytes` counts all supplied bytes plus one comma between field
/// values. Empty list elements are accepted. Each field value must contain
/// complete links, with no quoted string split across field values.
///
/// ```
/// # fn example() -> Result<(), phantom::LinkParseError> {
/// let headers = http::HeaderMap::from_iter([
///     (http::header::LINK, http::HeaderValue::from_static("</page/2>; rel=next")),
/// ]);
/// let links = phantom::parse_link_headers(
///     headers.get_all(http::header::LINK).iter().map(http::HeaderValue::as_bytes),
///     16 * 1024,
/// )?;
/// assert_eq!(links[0].target(), "/page/2");
/// assert!(links[0].has_relation("next"));
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`LinkParseError`] for invalid field syntax, URI references,
/// first `rel` or `anchor` values, or input exceeding `maximum_bytes`.
/// Errors identify the field value and byte offset without retaining input.
/// A failure returns no partial list.
pub fn parse_link_headers<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
    maximum_bytes: usize,
) -> Result<Vec<Link>, LinkParseError> {
    let mut links = Vec::new();
    let mut input_bytes = 0_usize;
    for (value_index, value) in values.into_iter().enumerate() {
        input_bytes = input_bytes
            .checked_add(usize::from(value_index != 0))
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= maximum_bytes)
            .ok_or_else(|| {
                LinkParseError::new(LinkParseErrorKind::InputTooLarge, value_index, 0)
            })?;
        let mut parser = Parser {
            bytes: value,
            offset: 0,
            value_index,
        };
        loop {
            parser.skip_whitespace();
            match parser.peek() {
                None => break,
                Some(b',') => parser.offset += 1,
                _ => {
                    links.push(parser.link()?);
                    parser.skip_whitespace();
                    match parser.peek() {
                        None | Some(b',') => {}
                        _ => return Err(parser.error(LinkParseErrorKind::InvalidSyntax)),
                    }
                }
            }
        }
    }
    Ok(links)
}

/// One parsed link, with its URI reference and ordered parameters.
///
/// Debug formatting redacts the target, relations, and parameter contents.
#[derive(Clone, Eq, PartialEq)]
pub struct Link {
    target: String,
    parameters: Vec<LinkParameter>,
    relations: Vec<String>,
    anchor: Option<String>,
}

impl Link {
    /// Returns the target's original URI-reference spelling.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns every parameter in received order, including duplicates.
    #[must_use]
    pub fn parameters(&self) -> &[LinkParameter] {
        &self.parameters
    }

    /// Returns the first parameter with this case-insensitive name.
    ///
    /// Use the first occurrence of `media`, `title`, or `type`. Extended
    /// parameters remain separate: this accessor does not prefer `title*`.
    #[must_use]
    pub fn first_parameter(&self, name: &str) -> Option<&LinkParameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name.eq_ignore_ascii_case(name))
    }

    /// Returns relation types from the first `rel`, with their spelling intact.
    #[must_use]
    pub fn relations(&self) -> &[String] {
        &self.relations
    }

    /// Compares registered and extension relations case-insensitively.
    ///
    /// Extension relations are absolute URIs, compared character by character.
    /// This comparison does not normalize URI components or percent escapes.
    #[must_use]
    pub fn has_relation(&self, relation: &str) -> bool {
        self.relations
            .iter()
            .any(|value| value.eq_ignore_ascii_case(relation))
    }

    /// Returns the first anchor's URI reference, without resolving it.
    ///
    /// An anchor changes the link's context. If you cannot apply that context,
    /// ignore the entire link rather than interpreting it without the anchor.
    #[must_use]
    pub fn anchor(&self) -> Option<&str> {
        self.anchor.as_deref()
    }
}

impl fmt::Debug for Link {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Link")
            .field("target", &"<redacted>")
            .field("parameter_count", &self.parameters.len())
            .field("relation_count", &self.relations.len())
            .field("has_anchor", &self.anchor.is_some())
            .finish()
    }
}

/// A parameter name and its token or unescaped quoted value.
///
/// Debug formatting redacts both the name and value.
#[derive(Clone, Eq, PartialEq)]
pub struct LinkParameter {
    name: String,
    value: Option<Vec<u8>>,
}

impl LinkParameter {
    /// Returns the parameter's original, case-insensitive name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns value bytes, or `None` when the parameter had no `=`.
    ///
    /// Quoted values have their quotes and backslash escapes removed. Their
    /// bytes can include HTTP's `obs-text` range, so they need not be UTF-8.
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }

    /// Returns whether the name ends in `*`, without decoding its value.
    #[must_use]
    pub fn is_extended(&self) -> bool {
        self.name.ends_with('*')
    }
}

impl fmt::Debug for LinkParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinkParameter")
            .field("name", &"<redacted>")
            .field("value", &"<redacted>")
            .field("has_value", &self.value.is_some())
            .finish()
    }
}

/// The category of a Link parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LinkParseErrorKind {
    /// The combined field-value size exceeded the supplied byte budget.
    InputTooLarge,
    /// A link delimiter or separator is missing or invalid.
    InvalidSyntax,
    /// The target is not an ASCII URI reference.
    InvalidTarget,
    /// A parameter name, token, or quoted string is invalid.
    InvalidParameter,
    /// The first `rel` is not a nonempty list of relation types.
    InvalidRelation,
    /// The first `anchor` does not have a valid URI-reference value.
    InvalidAnchor,
}

/// A parsing failure with its location, without any header contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkParseError {
    kind: LinkParseErrorKind,
    value_index: usize,
    byte_offset: usize,
}

impl LinkParseError {
    fn new(kind: LinkParseErrorKind, value_index: usize, byte_offset: usize) -> Self {
        Self {
            kind,
            value_index,
            byte_offset,
        }
    }

    /// Returns the failure category.
    #[must_use]
    pub const fn kind(&self) -> LinkParseErrorKind {
        self.kind
    }

    /// Returns the zero-based index of the supplied field value.
    #[must_use]
    pub const fn value_index(&self) -> usize {
        self.value_index
    }

    /// Returns the zero-based byte offset within that field value.
    ///
    /// A size-limit failure points to offset zero of the value exceeding it.
    #[must_use]
    pub const fn byte_offset(&self) -> usize {
        self.byte_offset
    }
}

impl fmt::Display for LinkParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid Link header ({:?}) at value {}, byte {}",
            self.kind, self.value_index, self.byte_offset
        )
    }
}

impl StdError for LinkParseError {}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
    value_index: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.offset += 1;
        }
    }

    fn error(&self, kind: LinkParseErrorKind) -> LinkParseError {
        LinkParseError::new(kind, self.value_index, self.offset)
    }

    fn link(&mut self) -> Result<Link, LinkParseError> {
        if self.peek() != Some(b'<') {
            return Err(self.error(LinkParseErrorKind::InvalidSyntax));
        }
        self.offset += 1;
        let target_offset = self.offset;
        while !matches!(self.peek(), None | Some(b'>')) {
            self.offset += 1;
        }
        if self.peek().is_none() {
            return Err(self.error(LinkParseErrorKind::InvalidSyntax));
        }
        let target = std::str::from_utf8(&self.bytes[target_offset..self.offset])
            .ok()
            .filter(|value| valid_uri_reference(value))
            .ok_or_else(|| {
                LinkParseError::new(
                    LinkParseErrorKind::InvalidTarget,
                    self.value_index,
                    target_offset,
                )
            })?
            .to_owned();
        self.offset += 1;
        let mut link = Link {
            target,
            parameters: Vec::new(),
            relations: Vec::new(),
            anchor: None,
        };
        let mut has_rel = false;
        let mut has_anchor = false;
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b';') {
                break;
            }
            self.offset += 1;
            let (parameter, value_offset) = self.parameter()?;
            if !has_rel && parameter.name.eq_ignore_ascii_case("rel") {
                has_rel = true;
                link.relations = parameter
                    .value
                    .as_deref()
                    .and_then(parse_relations)
                    .ok_or_else(|| {
                        LinkParseError::new(
                            LinkParseErrorKind::InvalidRelation,
                            self.value_index,
                            value_offset,
                        )
                    })?;
            }
            if !has_anchor && parameter.name.eq_ignore_ascii_case("anchor") {
                has_anchor = true;
                link.anchor = Some(
                    parameter
                        .value
                        .as_deref()
                        .and_then(|value| std::str::from_utf8(value).ok())
                        .filter(|value| valid_uri_reference(value))
                        .ok_or_else(|| {
                            LinkParseError::new(
                                LinkParseErrorKind::InvalidAnchor,
                                self.value_index,
                                value_offset,
                            )
                        })?
                        .to_owned(),
                );
            }
            link.parameters.push(parameter);
        }
        Ok(link)
    }

    fn parameter(&mut self) -> Result<(LinkParameter, usize), LinkParseError> {
        self.skip_whitespace();
        let start = self.offset;
        while self.peek().is_some_and(is_token) {
            self.offset += 1;
        }
        if start == self.offset {
            return Err(self.error(LinkParseErrorKind::InvalidParameter));
        }
        let name = std::str::from_utf8(&self.bytes[start..self.offset])
            .map_err(|_| self.error(LinkParseErrorKind::InvalidParameter))?
            .to_owned();
        self.skip_whitespace();
        let value = if self.peek() == Some(b'=') {
            self.offset += 1;
            self.skip_whitespace();
            let value_offset = self.offset;
            let value = if self.peek() == Some(b'"') {
                self.quoted_value()?
            } else {
                let start = self.offset;
                while self.peek().is_some_and(is_token) {
                    self.offset += 1;
                }
                if start == self.offset {
                    return Err(self.error(LinkParseErrorKind::InvalidParameter));
                }
                self.bytes[start..self.offset].to_vec()
            };
            return Ok((
                LinkParameter {
                    name,
                    value: Some(value),
                },
                value_offset,
            ));
        } else {
            None
        };
        Ok((LinkParameter { name, value }, self.offset))
    }

    fn quoted_value(&mut self) -> Result<Vec<u8>, LinkParseError> {
        self.offset += 1;
        let mut value = Vec::new();
        loop {
            match self.peek() {
                Some(b'"') => {
                    self.offset += 1;
                    return Ok(value);
                }
                Some(b'\\') => {
                    self.offset += 1;
                    match self.peek() {
                        Some(byte @ (b'\t' | b' '..=b'~' | 0x80..=0xff)) => {
                            value.push(byte);
                            self.offset += 1;
                        }
                        _ => return Err(self.error(LinkParseErrorKind::InvalidParameter)),
                    }
                }
                Some(byte @ (b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff)) => {
                    value.push(byte);
                    self.offset += 1;
                }
                _ => return Err(self.error(LinkParseErrorKind::InvalidParameter)),
            }
        }
    }
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn parse_relations(value: &[u8]) -> Option<Vec<String>> {
    let value = std::str::from_utf8(value).ok()?;
    let mut relations = Vec::new();
    for relation in value.split(' ').filter(|relation| !relation.is_empty()) {
        let registered = relation
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            && relation
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
        if !(registered || has_scheme(relation) && valid_uri_reference(relation)) {
            return None;
        }
        relations.push(relation.to_owned());
    }
    if value.starts_with(' ') || value.ends_with(' ') || relations.is_empty() {
        return None;
    }
    Some(relations)
}

// RFC 3986 Appendix A. Validate references without URL normalization or
// scheme-specific interpretation; percent-encoded octets remain encoded.
fn valid_uri_reference(value: &str) -> bool {
    if !value.is_ascii() {
        return false;
    }
    let (before_fragment, fragment) = value
        .split_once('#')
        .map_or((value, None), |(head, tail)| (head, Some(tail)));
    if fragment.is_some_and(|value| !component(value, true)) {
        return false;
    }
    let (hierarchy, query) = before_fragment
        .split_once('?')
        .map_or((before_fragment, None), |(head, tail)| (head, Some(tail)));
    if query.is_some_and(|value| !component(value, true)) {
        return false;
    }
    let scheme = has_scheme(hierarchy);
    let path = if scheme {
        let Some((_, path)) = hierarchy.split_once(':') else {
            return false;
        };
        path
    } else {
        hierarchy
    };
    if let Some(authority_and_path) = path.strip_prefix("//") {
        let (authority, path) = authority_and_path
            .split_once('/')
            .map_or((authority_and_path, ""), |(host, path)| (host, path));
        return valid_authority(authority) && component(path, false);
    }
    if !scheme
        && !path.starts_with('/')
        && path
            .split('/')
            .next()
            .is_some_and(|segment| segment.contains(':'))
    {
        return false;
    }
    component(path, false)
}

fn has_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn component(value: &str, allow_question_mark: bool) -> bool {
    encoded_component(value, |byte| {
        unreserved(byte)
            || sub_delimiter(byte)
            || matches!(byte, b':' | b'@' | b'/')
            || (allow_question_mark && byte == b'?')
    })
}

fn valid_authority(value: &str) -> bool {
    let host_port = if let Some((user_info, host_port)) = value.rsplit_once('@') {
        if !encoded_component(user_info, |byte| {
            unreserved(byte) || sub_delimiter(byte) || byte == b':'
        }) {
            return false;
        }
        host_port
    } else {
        value
    };
    if let Some(literal_and_port) = host_port.strip_prefix('[') {
        let Some((literal, port)) = literal_and_port.split_once(']') else {
            return false;
        };
        let valid_literal = if let Some(version_and_address) = literal
            .strip_prefix('v')
            .or_else(|| literal.strip_prefix('V'))
        {
            version_and_address
                .split_once('.')
                .is_some_and(|(version, address)| {
                    !version.is_empty()
                        && version.bytes().all(|byte| byte.is_ascii_hexdigit())
                        && !address.is_empty()
                        && address
                            .bytes()
                            .all(|byte| unreserved(byte) || sub_delimiter(byte) || byte == b':')
                })
        } else {
            literal.parse::<Ipv6Addr>().is_ok()
        };
        return valid_literal
            && (port.is_empty()
                || port
                    .strip_prefix(':')
                    .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit())));
    }
    let (host, port) = host_port
        .split_once(':')
        .map_or((host_port, None), |(host, port)| (host, Some(port)));
    encoded_component(host, |byte| unreserved(byte) || sub_delimiter(byte))
        && port.is_none_or(|port| port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn encoded_component(value: &str, allowed: impl Fn(u8) -> bool) -> bool {
    let bytes = value.as_bytes();
    let mut offset = 0;
    while let Some(&byte) = bytes.get(offset) {
        if byte == b'%' {
            if !bytes.get(offset + 1).is_some_and(u8::is_ascii_hexdigit)
                || !bytes.get(offset + 2).is_some_and(u8::is_ascii_hexdigit)
            {
                return false;
            }
            offset += 3;
        } else {
            if !allowed(byte) {
                return false;
            }
            offset += 1;
        }
    }
    true
}

fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)
}
fn sub_delimiter(byte: u8) -> bool {
    b"!$&'()*+,;=".contains(&byte)
}

#[cfg(test)]
mod tests;
