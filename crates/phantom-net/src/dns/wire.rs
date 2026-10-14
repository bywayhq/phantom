//! Bounded DNS messages for an explicitly configured HTTPS resolver.
//!
//! This codec performs no I/O or caching. Callers own exchange deadlines and
//! subtract response age and elapsed exchange time from the returned TTLs.

use std::{collections::HashMap, error::Error, fmt, net::IpAddr, num::NonZeroU16};

use hickory_resolver::proto::{
    op::{Edns, Header, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, LowerName, Name, RData, Record, RecordType,
        rdata::opt::{EdnsCode, EdnsOption},
    },
    serialize::binary::{BinDecodable, BinDecoder},
};

use super::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup};

/// Largest DNS message carried by one HTTPS exchange (RFC 8484 section 6).
pub const MAX_MESSAGE_BYTES: usize = 65_535;
/// Maximum CNAME hops across a query and its codec-created follow-ups.
pub const MAX_CNAME_HOPS: usize = 16;

/// The supported IN question types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsWireQueryKind {
    /// IPv4 addresses.
    A,
    /// IPv6 addresses.
    Aaaa,
    /// HTTPS service bindings.
    Https,
}

impl DnsWireQueryKind {
    const fn record_type(self) -> RecordType {
        match self {
            Self::A => RecordType::A,
            Self::Aaaa => RecordType::AAAA,
            Self::Https => RecordType::HTTPS,
        }
    }
}

/// An encoded question and the identity required of its response.
///
/// Cloning preserves its CNAME budget. No transport or browser policy is
/// selected here. In particular, zero IDs and 128-byte padding are explicit
/// constructor arguments, not defaults inferred from a client family.
#[derive(Clone)]
pub struct DnsWireQuery {
    name: Name,
    kind: DnsWireQueryKind,
    id: u16,
    padding_block: Option<NonZeroU16>,
    bytes: Box<[u8]>,
    visited: Vec<Name>,
    chain_ttl: Option<u32>,
}

impl fmt::Debug for DnsWireQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsWireQuery")
            .field("kind", &self.kind)
            .field("id", &self.id)
            .field("cname_hops", &self.cname_hops())
            .finish_non_exhaustive()
    }
}

impl DnsWireQuery {
    /// Encodes one fully qualified, ASCII, lowercase IN question with RD set.
    ///
    /// `name` is a DNS query name, including any HTTPS service-port prefix.
    /// A missing root dot is added. `padding_block` adds an EDNS(0) padding
    /// option (RFC 7830) so the entire message is a multiple of that size.
    /// Its bytes are zero and its advertised UDP payload size is 4096.
    ///
    /// # Errors
    ///
    /// Returns an input error for an empty, root, non-ASCII or invalid name,
    /// or padding that would exceed [`MAX_MESSAGE_BYTES`].
    pub fn new(
        name: &str,
        kind: DnsWireQueryKind,
        id: u16,
        padding_block: Option<NonZeroU16>,
    ) -> Result<Self, DnsWireError> {
        if name.is_empty() || !name.is_ascii() {
            return Err(DnsWireError::new(DnsWireErrorKind::InvalidQuery));
        }
        let mut name = Name::from_ascii(name)
            .map_err(|error| DnsWireError::with_source(DnsWireErrorKind::InvalidQuery, error))?
            .to_lowercase();
        name.set_fqdn(true);
        if name.is_root() {
            return Err(DnsWireError::new(DnsWireErrorKind::InvalidQuery));
        }
        let bytes = encode(&name, kind, id, padding_block)?;
        Ok(Self {
            visited: vec![name.clone()],
            name,
            kind,
            id,
            padding_block,
            bytes,
            chain_ttl: None,
        })
    }

    /// Returns the complete DNS message, without a TCP length prefix.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the current canonical question name, including its root dot.
    #[must_use]
    pub fn name(&self) -> String {
        self.name.to_ascii()
    }

    /// Returns the question type.
    #[must_use]
    pub const fn kind(&self) -> DnsWireQueryKind {
        self.kind
    }

    /// Returns how many CNAME hops preceded this question.
    #[must_use]
    pub fn cname_hops(&self) -> usize {
        self.visited.len() - 1
    }

    /// Validates the complete response and extracts only its terminal answer.
    ///
    /// A CNAME-only answer returns a follow-up carrying the same question
    /// type, ID, padding policy, visited names and minimum chain TTL. HTTPS
    /// AliasMode and ServiceMode TargetName values are returned as records;
    /// neither starts another query here.
    ///
    /// # Errors
    ///
    /// Rejects oversized, incomplete, trailing, compressed-name-invalid,
    /// truncated or mismatched responses, server failures, conflicting or
    /// looping aliases, and answers outside the terminal owner.
    pub fn parse_response(&self, bytes: &[u8]) -> Result<DnsWireResult, DnsWireError> {
        let (message, https_records) = decode_response(bytes)?;
        if message.metadata.id != self.id
            || message.metadata.message_type != MessageType::Response
            || message.metadata.op_code != OpCode::Query
            || message.queries.len() != 1
            || message.queries[0].name != self.name
            || message.queries[0].query_type != self.kind.record_type()
            || message.queries[0].query_class != DNSClass::IN
        {
            return Err(DnsWireError::new(DnsWireErrorKind::Mismatched));
        }
        if message.metadata.truncation {
            return Err(DnsWireError::new(DnsWireErrorKind::Truncated));
        }
        let code = message.metadata.response_code;
        if !matches!(code, ResponseCode::NoError | ResponseCode::NXDomain) {
            return Err(DnsWireError {
                kind: DnsWireErrorKind::Server,
                source: None,
                response_code: Some(u16::from(code)),
            });
        }
        self.extract(message, https_records, code)
    }

    fn extract(
        &self,
        message: Message,
        https_records: Vec<Option<HttpsRecord>>,
        code: ResponseCode,
    ) -> Result<DnsWireResult, DnsWireError> {
        let mut aliases: HashMap<LowerName, (Name, u32)> = HashMap::new();
        for record in &message.answers {
            if record.dns_class != DNSClass::IN {
                continue;
            }
            if let RData::CNAME(target) = &record.data {
                let key = LowerName::new(&record.name);
                let value = (target.0.to_lowercase(), record.ttl);
                if let Some((previous, ttl)) = aliases.get_mut(&key) {
                    if *previous != value.0 {
                        return Err(DnsWireError::new(DnsWireErrorKind::ConflictingAlias));
                    }
                    *ttl = (*ttl).min(value.1);
                } else {
                    aliases.insert(key, value);
                }
            }
        }
        let mut terminal = self.name.clone();
        let mut visited = self.visited.clone();
        let mut chain_ttl = self.chain_ttl;
        let mut followed = false;
        while let Some((target, ttl)) = aliases.remove(&LowerName::new(&terminal)) {
            if visited.contains(&target) {
                return Err(DnsWireError::new(DnsWireErrorKind::AliasLoop));
            }
            if visited.len() > MAX_CNAME_HOPS {
                return Err(DnsWireError::new(DnsWireErrorKind::AliasLimit));
            }
            if target.is_root() {
                return Err(DnsWireError::new(DnsWireErrorKind::Malformed));
            }
            visited.push(target.clone());
            terminal = target;
            chain_ttl = minimum_ttl(chain_ttl, ttl);
            followed = true;
        }
        if !aliases.is_empty() {
            return Err(DnsWireError::new(DnsWireErrorKind::UnexpectedOwner));
        }

        let mut addresses = Vec::new();
        let mut answers = Vec::new();
        let mut ttl = chain_ttl;
        for (record, https) in message.answers.iter().zip(https_records) {
            if record.dns_class != DNSClass::IN
                || record.data.record_type() != self.kind.record_type()
            {
                continue;
            }
            if record.name != terminal {
                return Err(DnsWireError::new(DnsWireErrorKind::UnexpectedOwner));
            }
            ttl = minimum_ttl(ttl, record.ttl);
            match &record.data {
                RData::A(address) => addresses.push(IpAddr::V4(address.0)),
                RData::AAAA(address) => addresses.push(IpAddr::V6(address.0)),
                RData::Update0(RecordType::HTTPS) => {
                    let Some(https) = https else {
                        return Err(DnsWireError::new(DnsWireErrorKind::Malformed));
                    };
                    answers.push(HttpsRecordAnswer::new(
                        terminal.to_ascii().trim_end_matches('.'),
                        chain_ttl.map_or(record.ttl, |chain| chain.min(record.ttl)),
                        https,
                    ));
                }
                _ => return Err(DnsWireError::new(DnsWireErrorKind::Malformed)),
            }
        }
        let has_answers = !addresses.is_empty() || !answers.is_empty();
        if code == ResponseCode::NXDomain && has_answers {
            return Err(DnsWireError::new(DnsWireErrorKind::Malformed));
        }
        if has_answers {
            return match self.kind {
                DnsWireQueryKind::Https => {
                    Ok(DnsWireResult::Https(HttpsRecordLookup::new(answers, None)))
                }
                DnsWireQueryKind::A | DnsWireQueryKind::Aaaa => {
                    Ok(DnsWireResult::Addresses(DnsAddressRecords {
                        addresses: addresses.into_boxed_slice(),
                        // Every selected address has supplied a TTL.
                        ttl: ttl.unwrap_or(0),
                    }))
                }
            };
        }

        let negative_ttl = message
            .authorities
            .iter()
            .filter(|record| record.dns_class == DNSClass::IN && record.name.zone_of(&terminal))
            .filter_map(|record| match &record.data {
                RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
                _ => None,
            })
            .min()
            .map(|ttl| chain_ttl.map_or(ttl, |chain| chain.min(ttl)));
        if code == ResponseCode::NXDomain || negative_ttl.is_some() || !followed {
            if code == ResponseCode::NoError
                && negative_ttl.is_none()
                && message.authorities.iter().any(|record| {
                    record.dns_class == DNSClass::IN
                        && matches!(record.data, RData::NS(_))
                        && record.name.zone_of(&terminal)
                })
            {
                return Err(DnsWireError::new(DnsWireErrorKind::Referral));
            }
            return Ok(DnsWireResult::Negative(DnsNegativeAnswer {
                kind: if code == ResponseCode::NXDomain {
                    DnsNegativeKind::NxDomain
                } else {
                    DnsNegativeKind::NoData
                },
                ttl: negative_ttl,
            }));
        }
        let bytes = encode(&terminal, self.kind, self.id, self.padding_block)?;
        Ok(DnsWireResult::Cname(DnsWireFollowUp {
            query: Self {
                name: terminal,
                kind: self.kind,
                id: self.id,
                padding_block: self.padding_block,
                bytes,
                visited,
                chain_ttl,
            },
        }))
    }
}

fn minimum_ttl(current: Option<u32>, ttl: u32) -> Option<u32> {
    Some(current.map_or(ttl, |current| current.min(ttl)))
}

fn encode(
    name: &Name,
    kind: DnsWireQueryKind,
    id: u16,
    padding_block: Option<NonZeroU16>,
) -> Result<Box<[u8]>, DnsWireError> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name.clone(), kind.record_type()));
    if let Some(block) = padding_block {
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.options_mut()
            .insert(EdnsOption::Unknown(12, Vec::new()));
        message.edns = Some(edns);
        let length = message
            .to_vec()
            .map_err(|error| DnsWireError::with_source(DnsWireErrorKind::InvalidQuery, error))?
            .len();
        let block = usize::from(block.get());
        let padding = (block - length % block) % block;
        if length + padding > MAX_MESSAGE_BYTES {
            return Err(DnsWireError::new(DnsWireErrorKind::TooLarge));
        }
        if let Some(edns) = &mut message.edns {
            edns.options_mut().remove(EdnsCode::Padding);
            edns.options_mut()
                .insert(EdnsOption::Unknown(12, vec![0; padding]));
        }
    }
    let bytes = message
        .to_vec()
        .map_err(|error| DnsWireError::with_source(DnsWireErrorKind::InvalidQuery, error))?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(DnsWireError::new(DnsWireErrorKind::TooLarge));
    }
    Ok(bytes.into_boxed_slice())
}

/// Uses the existing HTTPS parser on original RDATA, including AliasMode's
/// ignored parameters. Hickory owns names, other RDATA and EDNS validation.
fn decode_response(bytes: &[u8]) -> Result<(Message, Vec<Option<HttpsRecord>>), DnsWireError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(DnsWireError::new(DnsWireErrorKind::TooLarge));
    }
    if bytes.len() < 12 || bytes[3] & 0x40 != 0 {
        return Err(DnsWireError::new(DnsWireErrorKind::Malformed));
    }
    let counts = [4, 6, 8, 10]
        .map(|offset| usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]])));
    if counts[0] != 1 {
        return Err(DnsWireError::new(DnsWireErrorKind::Mismatched));
    }
    // A question needs at least five bytes and each RR needs eleven, even
    // with a root owner and empty RDATA. Reject impossible allocation counts.
    if bytes.len() < 17 || counts[1..].iter().sum::<usize>() > (bytes.len() - 17) / 11 {
        return Err(DnsWireError::new(DnsWireErrorKind::Malformed));
    }
    let mut decoder = BinDecoder::new(bytes);
    let read_error = |error| DnsWireError::with_source(DnsWireErrorKind::Malformed, error);
    let header = Header::read(&mut decoder).map_err(read_error)?;
    let question = Query::read(&mut decoder).map_err(read_error)?;
    let mut message = Message::new(
        header.metadata.id,
        header.metadata.message_type,
        header.metadata.op_code,
    );
    message.metadata = header.metadata;
    message.queries.push(question);
    let mut https_records = Vec::with_capacity(counts[1]);
    for _ in 0..counts[1] {
        let start = u16::try_from(decoder.index())
            .map_err(|_| DnsWireError::new(DnsWireErrorKind::Malformed))?;
        let name = Name::read(&mut decoder).map_err(read_error)?;
        let kind = decoder.read_u16().map_err(read_error)?.unverified();
        let class = decoder.read_u16().map_err(read_error)?.unverified();
        let ttl = decoder.read_u32().map_err(read_error)?.unverified();
        let length = decoder.read_u16().map_err(read_error)?.unverified();
        let rdata = decoder
            .read_slice(usize::from(length))
            .map_err(read_error)?
            .unverified();
        if kind == 65 && class == 1 {
            let https = HttpsRecord::from_rdata(rdata)
                .map_err(|error| DnsWireError::with_source(DnsWireErrorKind::Malformed, error))?;
            // Internal marker only: the parsed HTTPS value is kept beside
            // this record. It is never decoded or returned as Update0.
            message
                .answers
                .push(Record::update0(name, ttl, RecordType::HTTPS));
            https_records.push(Some(https));
        } else {
            let mut record_decoder = decoder.clone(start);
            let (records, _, _) =
                Message::read_records(&mut record_decoder, 1, false, header.metadata.op_code)
                    .map_err(read_error)?;
            if record_decoder.index() != decoder.index() {
                return Err(DnsWireError::new(DnsWireErrorKind::Malformed));
            }
            message.answers.extend(records);
            https_records.push(None);
        }
    }
    let (authorities, _, _) =
        Message::read_records(&mut decoder, counts[2], false, header.metadata.op_code)
            .map_err(read_error)?;
    let (additionals, edns, signature) =
        Message::read_records(&mut decoder, counts[3], true, header.metadata.op_code)
            .map_err(read_error)?;
    if let Some(edns) = &edns {
        // RFC 7830 section 3 permits at most one Padding option per message.
        if edns.options().get_all(EdnsCode::Padding).len() > 1 {
            return Err(DnsWireError::new(DnsWireErrorKind::Malformed));
        }
        message.metadata.merge_response_code(edns.rcode_high());
    }
    message.authorities = authorities;
    message.additionals = additionals;
    message.edns = edns;
    message.signature = signature;
    if decoder.index() != bytes.len() {
        return Err(DnsWireError::new(DnsWireErrorKind::Malformed));
    }
    Ok((message, https_records))
}

/// One validated response outcome. No DNS result implies a route fallback.
#[derive(Debug)]
pub enum DnsWireResult {
    /// Ordered terminal A or AAAA records.
    Addresses(DnsAddressRecords),
    /// Ordered terminal HTTPS records.
    Https(HttpsRecordLookup),
    /// A CNAME-only response needs another query of the same type.
    Cname(DnsWireFollowUp),
    /// An NXDOMAIN or NODATA response, with its SOA-derived lifetime if any.
    Negative(DnsNegativeAnswer),
}

/// Address records in answer order, with the minimum address/CNAME TTL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAddressRecords {
    addresses: Box<[IpAddr]>,
    ttl: u32,
}

impl DnsAddressRecords {
    /// Returns addresses without deduplicating or reordering them.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Returns remaining DNS lifetime before HTTP age/exchange adjustments.
    #[must_use]
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }
}

/// A follow-up with the CNAME budget and minimum TTL retained.
#[derive(Clone, Debug)]
pub struct DnsWireFollowUp {
    query: DnsWireQuery,
}

impl DnsWireFollowUp {
    /// Returns the minimum TTL of all preceding aliases.
    #[must_use]
    pub fn chain_ttl(&self) -> Option<u32> {
        self.query.chain_ttl
    }

    /// Returns the next query without resetting alias state.
    #[must_use]
    pub fn into_query(self) -> DnsWireQuery {
        self.query
    }
}

/// The absence reported by a DNS response, not an HTTP transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsNegativeKind {
    /// The terminal name does not exist.
    NxDomain,
    /// The terminal name has no records of the requested type.
    NoData,
}

/// A negative DNS answer and its cache lifetime.
///
/// A lifetime requires an IN SOA owned by an ancestor of the terminal name,
/// and is the minimum of SOA TTL, SOA MINIMUM and any CNAME TTL. No SOA means
/// no cache lifetime. This does not establish DNSSEC authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsNegativeAnswer {
    kind: DnsNegativeKind,
    ttl: Option<u32>,
}

impl DnsNegativeAnswer {
    /// Returns the DNS absence category.
    #[must_use]
    pub const fn kind(&self) -> DnsNegativeKind {
        self.kind
    }

    /// Returns the SOA-derived lifetime in seconds, including an explicit zero.
    #[must_use]
    pub const fn ttl(&self) -> Option<u32> {
        self.ttl
    }
}

/// A recoverable input, response-validation or DNS server failure.
#[derive(Debug)]
pub struct DnsWireError {
    kind: DnsWireErrorKind,
    source: Option<Box<dyn Error + Send + Sync>>,
    response_code: Option<u16>,
}

/// The stage at which a DNS wire exchange became unusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsWireErrorKind {
    /// Invalid query name or encoding configuration.
    InvalidQuery,
    /// Message exceeds the DNS-over-HTTPS wire limit.
    TooLarge,
    /// Incomplete or structurally invalid DNS message.
    Malformed,
    /// Response identity, opcode, flags or question do not match.
    Mismatched,
    /// DNS truncation is not a complete HTTPS answer.
    Truncated,
    /// DNS server returned a failure other than NXDOMAIN.
    Server,
    /// CNAME traversal exceeds the shared bound.
    AliasLimit,
    /// CNAME traversal revisits a name.
    AliasLoop,
    /// One CNAME owner names different targets.
    ConflictingAlias,
    /// An answer is unrelated to the terminal owner.
    UnexpectedOwner,
    /// A delegation is not an authoritative negative answer.
    Referral,
}

impl DnsWireError {
    fn new(kind: DnsWireErrorKind) -> Self {
        Self {
            kind,
            source: None,
            response_code: None,
        }
    }

    fn with_source(kind: DnsWireErrorKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            source: Some(Box::new(source)),
            response_code: None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> DnsWireErrorKind {
        self.kind
    }

    /// Returns the full DNS RCODE for a server failure, including EDNS bits.
    #[must_use]
    pub const fn response_code(&self) -> Option<u16> {
        self.response_code
    }
}

impl fmt::Display for DnsWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DNS wire exchange failed: {:?}", self.kind)
    }
}

impl Error for DnsWireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| &**source as &(dyn Error + 'static))
    }
}

#[cfg(test)]
mod tests;
