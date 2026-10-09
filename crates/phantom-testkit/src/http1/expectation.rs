//! Select and compare one request from a retained capture.

use std::{collections::BTreeMap, error::Error, fmt};

use super::{CaptureError, CaptureLimits, RequestHeadCapture};

/// Identity and selection recorded alongside an expected request.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestMetadata {
    browser: String,
    build: String,
    platform: String,
    captured_at_unix: u64,
    launch_mode: String,
    scenario: String,
    run: usize,
    request: usize,
    request_kind: String,
}

impl fmt::Debug for RequestMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestMetadata")
            .field("run", &self.run)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

impl RequestMetadata {
    /// Returns the recorded browser name.
    #[must_use]
    pub fn browser(&self) -> &str {
        &self.browser
    }
    /// Returns the exact recorded build string.
    #[must_use]
    pub fn build(&self) -> &str {
        &self.build
    }
    /// Returns the recorded operating system and architecture.
    #[must_use]
    pub fn platform(&self) -> &str {
        &self.platform
    }
    /// Returns the recorded Unix timestamp in seconds.
    #[must_use]
    pub const fn captured_at_unix(&self) -> u64 {
        self.captured_at_unix
    }
    /// Returns the recorded browser launch mode.
    #[must_use]
    pub fn launch_mode(&self) -> &str {
        &self.launch_mode
    }
    /// Returns the capture scenario name.
    #[must_use]
    pub fn scenario(&self) -> &str {
        &self.scenario
    }
    /// Returns the zero-based run index.
    #[must_use]
    pub const fn run(&self) -> usize {
        self.run
    }
    /// Returns the zero-based request index within that run.
    #[must_use]
    pub const fn request(&self) -> usize {
        self.request
    }
    /// Returns the recorded request kind, such as `page` or `done`.
    #[must_use]
    pub fn request_kind(&self) -> &str {
        &self.request_kind
    }
}

/// An independently recorded request and its capture metadata.
///
/// The reader accepts `phantom-http2-websocket-v1` captures. It selects only
/// HTTP/1 line records and does not interpret TLS or HTTP/2 observations.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestExpectation {
    metadata: RequestMetadata,
    head: RequestHeadCapture,
    limits: CaptureLimits,
}

impl RequestExpectation {
    /// Selects one request from a bounded retained capture document.
    ///
    /// Run and request indexes are explicit. The selected run must have
    /// completed. Every declared header must be present and valid hex.
    /// Metadata is retained as recorded, rather than inferred from recipes.
    ///
    /// # Errors
    ///
    /// Returns [`ExpectationError`] for missing, duplicate, empty, malformed,
    /// oversized, or incomplete data. A selected HTTP/2 request has no HTTP/1
    /// line record and is rejected.
    pub fn from_retained(
        text: &str,
        run: usize,
        request: usize,
        maximum_fixture_bytes: usize,
        limits: CaptureLimits,
    ) -> Result<Self, ExpectationError> {
        if text.is_empty() {
            return Err(ExpectationError::EmptyFixture);
        }
        if text.len() > maximum_fixture_bytes {
            return Err(ExpectationError::FixtureLimitExceeded);
        }
        let mut fields = BTreeMap::new();
        for (line, record) in text.lines().enumerate() {
            let (key, value) = record
                .split_once('=')
                .ok_or(ExpectationError::InvalidRecord { line })?;
            if key.is_empty() || fields.insert(key, value).is_some() {
                return Err(ExpectationError::InvalidRecord { line });
            }
        }
        if required(&fields, "format")? != "phantom-http2-websocket-v1" {
            return Err(ExpectationError::UnsupportedFormat);
        }
        if run >= number(&fields, "repeat_count")? {
            return Err(ExpectationError::RunOutOfRange);
        }
        let prefix = format!("run_{run}");
        if required(&fields, &format!("{prefix}_timed_out"))? != "false" {
            return Err(ExpectationError::IncompleteRun);
        }
        if request >= number(&fields, &format!("{prefix}_request_count"))? {
            return Err(ExpectationError::RequestOutOfRange);
        }
        let key = format!("{prefix}_request_{request}");
        let mut attributes = BTreeMap::new();
        for attribute in required(&fields, &key)?.split(',') {
            let (name, value) = attribute
                .split_once(':')
                .ok_or(ExpectationError::InvalidField)?;
            if name.is_empty() || value.is_empty() || attributes.insert(name, value).is_some() {
                return Err(ExpectationError::InvalidField);
            }
        }
        let request_kind = required(&attributes, "kind")?.to_owned();
        let metadata = RequestMetadata {
            browser: required(&fields, "client")?.to_owned(),
            build: required(&fields, "client_version")?.to_owned(),
            platform: required(&fields, "operating_system")?.to_owned(),
            captured_at_unix: required(&fields, "captured_at_unix")?
                .parse()
                .map_err(|_| ExpectationError::InvalidField)?,
            launch_mode: required(&fields, "launch_mode")?.to_owned(),
            scenario: required(&fields, "scenario")?.to_owned(),
            run,
            request,
            request_kind,
        };
        let count = number(&fields, &format!("{key}_header_count"))?;
        if count > limits.max_headers {
            return Err(ExpectationError::Head(CaptureError::HeaderLimitExceeded));
        }
        let header_prefix = format!("{key}_header_");
        for field in fields
            .keys()
            .filter_map(|field| field.strip_prefix(&header_prefix))
        {
            if field != "count" {
                let index = field
                    .parse::<usize>()
                    .map_err(|_| ExpectationError::InvalidField)?;
                if index >= count || index.to_string() != field {
                    return Err(ExpectationError::InvalidField);
                }
            }
        }
        let mut bytes = Vec::new();
        append_hex_line(
            &mut bytes,
            required(&fields, &format!("{key}_line_hex"))?,
            limits,
            0,
        )?;
        for index in 0..count {
            append_hex_line(
                &mut bytes,
                required(&fields, &format!("{key}_header_{index}"))?,
                limits,
                index + 1,
            )?;
        }
        if bytes
            .len()
            .checked_add(2)
            .is_none_or(|size| size > limits.max_head_bytes)
        {
            return Err(ExpectationError::Head(CaptureError::HeadLimitExceeded));
        }
        bytes.extend_from_slice(b"\r\n");
        let head = RequestHeadCapture::parse(&bytes, limits).map_err(ExpectationError::Head)?;
        Ok(Self {
            metadata,
            head,
            limits,
        })
    }

    /// Returns the recorded identity and selected request indexes.
    #[must_use]
    pub const fn metadata(&self) -> &RequestMetadata {
        &self.metadata
    }
    /// Returns the expected bytes, including any explicit adjustments.
    #[must_use]
    pub const fn head(&self) -> &RequestHeadCapture {
        &self.head
    }

    /// Replaces only the expected request target, preserving method and version.
    ///
    /// # Errors
    ///
    /// Returns an input or limit error. The expectation stays unchanged on
    /// failure. Targets are not resolved or normalized.
    pub fn replace_target(&mut self, target: &[u8]) -> Result<(), ExpectationError> {
        if target.is_empty() || !target.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
            return Err(ExpectationError::Head(CaptureError::InvalidRequestLine));
        }
        if target.len() > self.limits.max_line_bytes {
            return Err(ExpectationError::Head(CaptureError::LineLimitExceeded {
                line: 0,
            }));
        }
        let mut bytes = self.head.method().to_vec();
        bytes.push(b' ');
        bytes.extend_from_slice(target);
        bytes.push(b' ');
        bytes.extend_from_slice(self.head.version());
        bytes.extend_from_slice(b"\r\n");
        for header in self.head.headers() {
            bytes.extend_from_slice(header.bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        self.head =
            RequestHeadCapture::parse(&bytes, self.limits).map_err(ExpectationError::Head)?;
        Ok(())
    }

    /// Replaces a Host or User-Agent value at one explicit header index.
    ///
    /// The name, case, and position stay unchanged. `value_bytes` includes
    /// whitespace after the colon. Duplicate headers are never changed together.
    ///
    /// # Errors
    ///
    /// Returns [`ExpectationError::InvalidAdjustment`] for the wrong index or
    /// header name. Invalid bytes or size bounds return a head error. The
    /// expectation stays unchanged on failure.
    pub fn replace_header_value(
        &mut self,
        index: usize,
        header: AdjustableHeader,
        value_bytes: &[u8],
    ) -> Result<(), ExpectationError> {
        let selected = self
            .head
            .headers()
            .get(index)
            .ok_or(ExpectationError::InvalidAdjustment)?;
        if !selected.name().eq_ignore_ascii_case(header.name()) {
            return Err(ExpectationError::InvalidAdjustment);
        }
        if !value_bytes
            .iter()
            .all(|byte| *byte == b'\t' || *byte >= 0x20 && *byte != 0x7f)
        {
            return Err(ExpectationError::Head(CaptureError::InvalidLine {
                line: index + 1,
            }));
        }
        if value_bytes.len() > self.limits.max_line_bytes {
            return Err(ExpectationError::Head(CaptureError::LineLimitExceeded {
                line: index + 1,
            }));
        }
        let mut bytes = self.head.request_line().to_vec();
        bytes.extend_from_slice(b"\r\n");
        for (slot, original) in self.head.headers().iter().enumerate() {
            if slot == index {
                bytes.extend_from_slice(original.name());
                bytes.push(b':');
                bytes.extend_from_slice(value_bytes);
            } else {
                bytes.extend_from_slice(original.bytes());
            }
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        self.head =
            RequestHeadCapture::parse(&bytes, self.limits).map_err(ExpectationError::Head)?;
        Ok(())
    }

    /// Compares request bytes without trimming, sorting, or ignoring headers.
    ///
    /// # Errors
    ///
    /// Returns the first typed mismatch location. Formatting contains indexes
    /// and counts, never request bytes.
    pub fn compare(&self, actual: &RequestHeadCapture) -> Result<(), RequestMismatch> {
        if let Some(byte) = first_difference(self.head.request_line(), actual.request_line()) {
            return Err(RequestMismatch {
                location: MismatchLocation::RequestLine { byte },
            });
        }
        if self.head.headers().len() != actual.headers().len() {
            return Err(RequestMismatch {
                location: MismatchLocation::HeaderCount {
                    expected: self.head.headers().len(),
                    actual: actual.headers().len(),
                },
            });
        }
        for (index, (expected, actual)) in
            self.head.headers().iter().zip(actual.headers()).enumerate()
        {
            if let Some(byte) = first_difference(expected.name(), actual.name()) {
                return Err(RequestMismatch {
                    location: MismatchLocation::HeaderName { index, byte },
                });
            }
            if let Some(byte) = first_difference(expected.value_bytes(), actual.value_bytes()) {
                return Err(RequestMismatch {
                    location: MismatchLocation::HeaderValue { index, byte },
                });
            }
        }
        Ok(())
    }
}

impl fmt::Debug for RequestExpectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestExpectation")
            .field("metadata", &self.metadata)
            .field("head", &self.head)
            .finish()
    }
}

/// Header names allowed for an explicit expectation adjustment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdjustableHeader {
    /// The captured authority header.
    Host,
    /// The captured browser identification header.
    UserAgent,
}
impl AdjustableHeader {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Host => b"Host",
            Self::UserAgent => b"User-Agent",
        }
    }
}

/// Numeric location of an exact request mismatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MismatchLocation {
    /// The request line differs.
    RequestLine {
        /// Byte offset within the request line.
        byte: usize,
    },
    /// The number of headers differs.
    HeaderCount {
        /// Expected count.
        expected: usize,
        /// Received count.
        actual: usize,
    },
    /// A header name differs, including case.
    HeaderName {
        /// Zero-based header position.
        index: usize,
        /// Byte offset within the name.
        byte: usize,
    },
    /// A header value differs, including whitespace.
    HeaderValue {
        /// Zero-based header position.
        index: usize,
        /// Byte offset after the colon.
        byte: usize,
    },
}

/// An exact comparison failure that omits expected and received bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestMismatch {
    location: MismatchLocation,
}
impl RequestMismatch {
    /// Returns the mismatch location.
    #[must_use]
    pub const fn location(&self) -> MismatchLocation {
        self.location
    }
}
impl fmt::Display for RequestMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP/1 request mismatch: {:?}", self.location)
    }
}
impl Error for RequestMismatch {}

/// A retained capture or explicit adjustment failure. Input bytes are omitted.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExpectationError {
    /// The retained document was empty.
    EmptyFixture,
    /// The retained document exceeded its byte bound.
    FixtureLimitExceeded,
    /// A record was malformed or repeated a key.
    InvalidRecord {
        /// Zero-based document line.
        line: usize,
    },
    /// The document used another format.
    UnsupportedFormat,
    /// A required record was missing or empty.
    MissingField,
    /// A count, timestamp, or request attribute was invalid.
    InvalidField,
    /// The selected run did not exist.
    RunOutOfRange,
    /// The selected request did not exist.
    RequestOutOfRange,
    /// The selected run timed out or had an invalid completion flag.
    IncompleteRun,
    /// A line contained malformed hex.
    InvalidHex,
    /// The selected header was absent or had another name.
    InvalidAdjustment,
    /// The decoded or adjusted request was invalid or exceeded its bounds.
    Head(CaptureError),
}
impl fmt::Display for ExpectationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecord { line } => {
                write!(f, "invalid retained capture record at line {line}")
            }
            Self::Head(error) => write!(f, "invalid expected request: {error}"),
            _ => write!(f, "retained HTTP/1 expectation error: {self:?}"),
        }
    }
}
impl Error for ExpectationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Head(error) => Some(error),
            _ => None,
        }
    }
}

fn required<'a>(fields: &BTreeMap<&str, &'a str>, key: &str) -> Result<&'a str, ExpectationError> {
    fields
        .get(key)
        .copied()
        .filter(|value| !value.is_empty())
        .ok_or(ExpectationError::MissingField)
}
fn number(fields: &BTreeMap<&str, &str>, key: &str) -> Result<usize, ExpectationError> {
    required(fields, key)?
        .parse()
        .map_err(|_| ExpectationError::InvalidField)
}
fn append_hex_line(
    bytes: &mut Vec<u8>,
    hex: &str,
    limits: CaptureLimits,
    line: usize,
) -> Result<(), ExpectationError> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return Err(ExpectationError::InvalidHex);
    }
    let length = hex.len() / 2;
    if length
        .checked_add(2)
        .is_none_or(|size| size > limits.max_line_bytes)
    {
        return Err(ExpectationError::Head(CaptureError::LineLimitExceeded {
            line,
        }));
    }
    if bytes
        .len()
        .checked_add(length)
        .and_then(|size| size.checked_add(2))
        .is_none_or(|size| size > limits.max_head_bytes)
    {
        return Err(ExpectationError::Head(CaptureError::HeadLimitExceeded));
    }
    for pair in hex.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0]).ok_or(ExpectationError::InvalidHex)?;
        let low = hex_digit(pair[1]).ok_or(ExpectationError::InvalidHex)?;
        let byte = high * 16 + low;
        if matches!(byte, b'\r' | b'\n') {
            return Err(ExpectationError::InvalidField);
        }
        bytes.push(byte);
    }
    bytes.extend_from_slice(b"\r\n");
    Ok(())
}
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
fn first_difference(expected: &[u8], actual: &[u8]) -> Option<usize> {
    expected
        .iter()
        .zip(actual)
        .position(|(left, right)| left != right)
        .or_else(|| (expected.len() != actual.len()).then_some(expected.len().min(actual.len())))
}

#[cfg(test)]
mod tests;
