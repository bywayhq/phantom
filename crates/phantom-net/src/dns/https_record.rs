//! HTTPS resource record RDATA (RFC 9460, DNS type 65).

use std::{
    error::Error as StdError,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
};

/// `mandatory` (RFC 9460 section 8).
const KEY_MANDATORY: u16 = 0;
/// `alpn` (RFC 9460 section 7.1).
const KEY_ALPN: u16 = 1;
/// `no-default-alpn` (RFC 9460 section 7.1).
const KEY_NO_DEFAULT_ALPN: u16 = 2;
/// `port` (RFC 9460 section 7.2).
const KEY_PORT: u16 = 3;
/// `ipv4hint` (RFC 9460 section 7.3).
const KEY_IPV4_HINT: u16 = 4;
/// `ech` (RFC 9460 section 14.3.2, defined by the TLS ECH SVCB binding).
const KEY_ECH: u16 = 5;
/// `ipv6hint` (RFC 9460 section 7.3).
const KEY_IPV6_HINT: u16 = 6;
/// The reserved "Invalid key" (RFC 9460 section 14.3.3).
const KEY_INVALID: u16 = 65535;

/// Longest wire-format domain name, including the root label (RFC 1035 section 2.3.4).
const MAX_NAME_LENGTH: usize = 255;
/// Longest label (RFC 1035 section 2.3.4).
const MAX_LABEL_LENGTH: usize = 63;

/// One HTTPS resource record, parsed from its RDATA.
///
/// A record with `SvcPriority` 0 is in AliasMode and names another domain to
/// query; any other priority is a ServiceMode record describing an endpoint
/// (RFC 9460 section 2.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpsRecord {
    /// An AliasMode record.
    Alias(AliasRecord),
    /// A ServiceMode record.
    Service(ServiceRecord),
}

impl HttpsRecord {
    /// Parses the RDATA of one HTTPS resource record.
    ///
    /// The whole RDATA must be consumed. An AliasMode record's SvcParams are
    /// ignored without being parsed, as RFC 9460 section 2.4.2 requires.
    ///
    /// # Errors
    ///
    /// Returns [`HttpsRecordError`] when the RDATA is truncated, its
    /// TargetName is compressed or not a valid name, its SvcParamKeys are not
    /// strictly increasing, a known SvcParam value is malformed, or a key
    /// listed in `mandatory` is absent (RFC 9460 sections 2.2 and 8).
    pub fn from_rdata(rdata: &[u8]) -> Result<Self, HttpsRecordError> {
        let mut reader = Reader::new(rdata);
        let priority = reader.u16()?;
        let target = TargetName::read(&mut reader)?;
        let Some(priority) = NonZeroU16::new(priority) else {
            return Ok(Self::Alias(AliasRecord { target }));
        };
        let mut record = ServiceRecord {
            priority,
            target,
            mandatory: Box::default(),
            alpn: Box::default(),
            no_default_alpn: false,
            port: None,
            ipv4_hint: Box::default(),
            ipv6_hint: Box::default(),
            ech: None,
            other: Box::default(),
        };
        let mut previous_key = None;
        let mut present = Vec::new();
        let mut other = Vec::new();
        while !reader.is_empty() {
            let key = reader.u16()?;
            if previous_key.is_some_and(|previous| key <= previous) {
                return Err(HttpsRecordError::new(HttpsRecordErrorKind::KeyOrder, key));
            }
            previous_key = Some(key);
            let length = usize::from(reader.u16()?);
            let value = reader.take(length)?;
            present.push(key);
            match key {
                KEY_MANDATORY => record.mandatory = parse_mandatory(value)?,
                KEY_ALPN => record.alpn = parse_alpn(value)?,
                KEY_NO_DEFAULT_ALPN if value.is_empty() => record.no_default_alpn = true,
                KEY_PORT => {
                    record.port = Some(u16::from_be_bytes(
                        value.try_into().map_err(|_| invalid(key))?,
                    ));
                }
                KEY_IPV4_HINT => record.ipv4_hint = parse_hints(key, value, Ipv4Addr::from)?,
                KEY_ECH if !value.is_empty() => {
                    record.ech = Some(EchConfigList(value.into()));
                }
                KEY_IPV6_HINT => record.ipv6_hint = parse_hints(key, value, Ipv6Addr::from)?,
                KEY_INVALID => {
                    return Err(HttpsRecordError::new(
                        HttpsRecordErrorKind::ReservedKey,
                        key,
                    ));
                }
                KEY_NO_DEFAULT_ALPN | KEY_ECH => return Err(invalid(key)),
                _ => other.push(SvcParam {
                    key,
                    value: value.into(),
                }),
            }
        }
        // Keys are strictly increasing, so a binary search finds each one.
        if let Some(&missing) = record
            .mandatory
            .iter()
            .find(|key| present.binary_search(key).is_err())
        {
            return Err(HttpsRecordError::new(
                HttpsRecordErrorKind::MissingMandatoryKey,
                missing,
            ));
        }
        record.other = other.into_boxed_slice();
        Ok(Self::Service(record))
    }

    /// Returns `SvcPriority`: 0 for AliasMode, otherwise the ServiceMode priority.
    #[must_use]
    pub const fn priority(&self) -> u16 {
        match self {
            Self::Alias(_) => 0,
            Self::Service(service) => service.priority.get(),
        }
    }

    /// Returns `TargetName`.
    #[must_use]
    pub const fn target(&self) -> &TargetName {
        match self {
            Self::Alias(alias) => &alias.target,
            Self::Service(service) => &service.target,
        }
    }
}

/// An AliasMode HTTPS record (RFC 9460 section 2.4.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasRecord {
    target: TargetName,
}

impl AliasRecord {
    /// Returns the aliased name; [`TargetName::Owner`] means the service is unavailable.
    #[must_use]
    pub const fn target(&self) -> &TargetName {
        &self.target
    }
}

/// A ServiceMode HTTPS record and its SvcParams (RFC 9460 sections 2.4.3 and 7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRecord {
    priority: NonZeroU16,
    target: TargetName,
    mandatory: Box<[u16]>,
    alpn: Box<[Box<[u8]>]>,
    no_default_alpn: bool,
    port: Option<u16>,
    ipv4_hint: Box<[Ipv4Addr]>,
    ipv6_hint: Box<[Ipv6Addr]>,
    ech: Option<EchConfigList>,
    other: Box<[SvcParam]>,
}

impl ServiceRecord {
    /// Returns `SvcPriority`; lower values are preferred.
    #[must_use]
    pub const fn priority(&self) -> NonZeroU16 {
        self.priority
    }

    /// Returns `TargetName`; [`TargetName::Owner`] means the record's owner name.
    #[must_use]
    pub const fn target(&self) -> &TargetName {
        &self.target
    }

    /// Returns the `mandatory` keys in increasing order; empty when absent.
    #[must_use]
    pub fn mandatory(&self) -> &[u16] {
        &self.mandatory
    }

    /// Returns the `alpn` protocol identifiers in record order; empty when absent.
    #[must_use]
    pub fn alpn(&self) -> &[Box<[u8]>] {
        &self.alpn
    }

    /// Returns whether `no-default-alpn` is present.
    ///
    /// Without it, the HTTPS default protocol `http/1.1` is supported in
    /// addition to [`Self::alpn`] (RFC 9460 section 7.1.2).
    #[must_use]
    pub const fn no_default_alpn(&self) -> bool {
        self.no_default_alpn
    }

    /// Returns `port`, the alternative port for this endpoint.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns `ipv4hint` in record order; empty when absent.
    #[must_use]
    pub fn ipv4_hint(&self) -> &[Ipv4Addr] {
        &self.ipv4_hint
    }

    /// Returns `ipv6hint` in record order; empty when absent.
    #[must_use]
    pub fn ipv6_hint(&self) -> &[Ipv6Addr] {
        &self.ipv6_hint
    }

    /// Returns the `ech` value, uninterpreted.
    #[must_use]
    pub const fn ech(&self) -> Option<&EchConfigList> {
        self.ech.as_ref()
    }

    /// Returns SvcParams with keys this parser does not interpret, in key order.
    #[must_use]
    pub fn other_params(&self) -> &[SvcParam] {
        &self.other
    }
}

/// A record's `TargetName`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetName {
    /// The root name `.`, which stands for the record's owner name in
    /// ServiceMode and for "service unavailable" in AliasMode.
    Owner,
    /// A domain name in dotted form, without the trailing root dot.
    ///
    /// Each label is printable ASCII other than `.`; case is preserved.
    Name(Box<str>),
}

impl TargetName {
    fn read(reader: &mut Reader<'_>) -> Result<Self, HttpsRecordError> {
        let mut dotted = String::new();
        let mut wire_length = 0;
        loop {
            let length = usize::from(reader.u8()?);
            wire_length += length + 1;
            if wire_length > MAX_NAME_LENGTH {
                return Err(target_name());
            }
            if length == 0 {
                break;
            }
            // RFC 9460 section 2.2: TargetName is uncompressed, so a pointer
            // (top bits 11) or an extended label type (01 or 10) is malformed.
            if length > MAX_LABEL_LENGTH {
                return Err(target_name());
            }
            let label = reader.take(length)?;
            if !label
                .iter()
                .all(|byte| byte.is_ascii_graphic() && *byte != b'.')
            {
                return Err(target_name());
            }
            if !dotted.is_empty() {
                dotted.push('.');
            }
            dotted.extend(label.iter().copied().map(char::from));
        }
        Ok(if dotted.is_empty() {
            Self::Owner
        } else {
            Self::Name(dotted.into_boxed_str())
        })
    }
}

/// The raw `ech` SvcParam value, an `ECHConfigList`.
///
/// Phantom retains these bytes without interpreting them; ECH is not yet
/// implemented.
#[derive(Clone, Eq, PartialEq)]
pub struct EchConfigList(Box<[u8]>);

impl EchConfigList {
    /// Returns the value bytes exactly as they appeared in the record.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for EchConfigList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EchConfigList")
            .field("len", &self.0.len())
            .finish()
    }
}

/// A SvcParam whose key this parser does not interpret, retained verbatim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SvcParam {
    key: u16,
    value: Box<[u8]>,
}

impl SvcParam {
    /// Returns the SvcParamKey.
    #[must_use]
    pub const fn key(&self) -> u16 {
        self.key
    }

    /// Returns the SvcParamValue bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Stable category of a malformed HTTPS record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HttpsRecordErrorKind {
    /// The RDATA ends inside a field.
    Truncated,
    /// `TargetName` is compressed, too long, or has a label that is not
    /// printable ASCII without `.`.
    TargetName,
    /// A SvcParamKey is not strictly greater than the one before it.
    KeyOrder,
    /// The reserved key 65535 is present.
    ReservedKey,
    /// A known SvcParam's value is malformed.
    InvalidParameter,
    /// A key listed in `mandatory` is absent from the record.
    MissingMandatoryKey,
}

/// A malformed HTTPS record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsRecordError {
    kind: HttpsRecordErrorKind,
    key: Option<u16>,
}

impl HttpsRecordError {
    const fn new(kind: HttpsRecordErrorKind, key: u16) -> Self {
        Self {
            kind,
            key: Some(key),
        }
    }

    const fn without_key(kind: HttpsRecordErrorKind) -> Self {
        Self { kind, key: None }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> HttpsRecordErrorKind {
        self.kind
    }

    /// Returns the SvcParamKey the failure concerns, when it concerns one.
    #[must_use]
    pub const fn key(&self) -> Option<u16> {
        self.key
    }
}

impl fmt::Display for HttpsRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            HttpsRecordErrorKind::Truncated => "truncated HTTPS record",
            HttpsRecordErrorKind::TargetName => "invalid HTTPS record target name",
            HttpsRecordErrorKind::KeyOrder => "HTTPS record keys are not strictly increasing",
            HttpsRecordErrorKind::ReservedKey => "HTTPS record uses the reserved key 65535",
            HttpsRecordErrorKind::InvalidParameter => "malformed HTTPS record parameter",
            HttpsRecordErrorKind::MissingMandatoryKey => "HTTPS record lacks a mandatory key",
        };
        match self.key {
            Some(key) => write!(formatter, "{message} (key {key})"),
            None => formatter.write_str(message),
        }
    }
}

impl StdError for HttpsRecordError {}

const fn invalid(key: u16) -> HttpsRecordError {
    HttpsRecordError::new(HttpsRecordErrorKind::InvalidParameter, key)
}

const fn target_name() -> HttpsRecordError {
    HttpsRecordError::without_key(HttpsRecordErrorKind::TargetName)
}

/// Parses `mandatory`: a non-empty, strictly increasing key list that does
/// not name `mandatory` itself (RFC 9460 section 8).
fn parse_mandatory(value: &[u8]) -> Result<Box<[u16]>, HttpsRecordError> {
    let (pairs, rest) = value.as_chunks::<2>();
    if pairs.is_empty() || !rest.is_empty() {
        return Err(invalid(KEY_MANDATORY));
    }
    let keys = pairs
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect::<Box<[u16]>>();
    let increasing = keys.windows(2).all(|pair| pair[0] < pair[1]);
    if !increasing || keys.contains(&KEY_MANDATORY) {
        return Err(invalid(KEY_MANDATORY));
    }
    Ok(keys)
}

/// Parses `alpn`: one or more non-empty length-prefixed identifiers (RFC 9460
/// section 7.1.1).
fn parse_alpn(value: &[u8]) -> Result<Box<[Box<[u8]>]>, HttpsRecordError> {
    if value.is_empty() {
        return Err(invalid(KEY_ALPN));
    }
    let mut reader = Reader::new(value);
    let mut identifiers = Vec::new();
    while !reader.is_empty() {
        let length = usize::from(reader.u8().map_err(|_| invalid(KEY_ALPN))?);
        if length == 0 {
            return Err(invalid(KEY_ALPN));
        }
        let identifier = reader.take(length).map_err(|_| invalid(KEY_ALPN))?;
        identifiers.push(Box::from(identifier));
    }
    Ok(identifiers.into_boxed_slice())
}

/// Parses `ipv4hint` or `ipv6hint`: one or more addresses (RFC 9460 section 7.3).
fn parse_hints<A, const N: usize>(
    key: u16,
    value: &[u8],
    address: fn([u8; N]) -> A,
) -> Result<Box<[A]>, HttpsRecordError> {
    let (addresses, rest) = value.as_chunks::<N>();
    if addresses.is_empty() || !rest.is_empty() {
        return Err(invalid(key));
    }
    Ok(addresses.iter().copied().map(address).collect())
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HttpsRecordError> {
        if self.remaining.len() < length {
            return Err(HttpsRecordError::without_key(
                HttpsRecordErrorKind::Truncated,
            ));
        }
        let (taken, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8, HttpsRecordError> {
        self.take(1).map(|byte| byte[0])
    }

    fn u16(&mut self) -> Result<u16, HttpsRecordError> {
        self.take(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
    }
}
