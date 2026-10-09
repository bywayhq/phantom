//! Capture one HTTP/1 request head without consuming its body.
//!
//! You can compare the exact bytes with a retained request using
//! [`expectation::RequestExpectation`]. These helpers do not parse bodies.

pub mod expectation;

use std::{error::Error, fmt, io};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::{Instant, timeout_at},
};

/// Explicit bounds for a request head, its lines, and its header count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureLimits {
    max_head_bytes: usize,
    max_line_bytes: usize,
    max_headers: usize,
}

impl CaptureLimits {
    /// Creates limits. Byte counts include CRLF and the final empty line.
    ///
    /// Zero limits are allowed and cause capture to fail at that boundary.
    #[must_use]
    pub const fn new(max_head_bytes: usize, max_line_bytes: usize, max_headers: usize) -> Self {
        Self {
            max_head_bytes,
            max_line_bytes,
            max_headers,
        }
    }
}

/// One header line, including its original case and whitespace.
#[derive(Clone, Eq, PartialEq)]
pub struct CapturedHeader {
    bytes: Vec<u8>,
    colon: usize,
}

impl CapturedHeader {
    /// Returns the line without its final CRLF.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the exact header name.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.bytes[..self.colon]
    }

    /// Returns everything after the colon, including surrounding whitespace.
    #[must_use]
    pub fn value_bytes(&self) -> &[u8] {
        &self.bytes[self.colon + 1..]
    }
}

impl fmt::Debug for CapturedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedHeader")
            .field("byte_count", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A complete request line and ordered headers with their original bytes.
///
/// Parsing checks line syntax, not routing, body framing, or Host semantics.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestHeadCapture {
    bytes: Vec<u8>,
    request_line: Vec<u8>,
    first_space: usize,
    second_space: usize,
    headers: Vec<CapturedHeader>,
}

impl RequestHeadCapture {
    /// Parses exactly one complete head, including its final CRLFCRLF.
    ///
    /// HTTP/1.0 and HTTP/1.1 request lines are accepted. Header values may
    /// contain non-ASCII bytes. Folded lines and bare LF are rejected.
    ///
    /// # Errors
    ///
    /// Returns a syntax, truncation, or limit error. Bytes after the head are
    /// rejected rather than treated as a body.
    pub fn parse(bytes: &[u8], limits: CaptureLimits) -> Result<Self, CaptureError> {
        if bytes.is_empty() {
            return Err(CaptureError::EmptyInput);
        }
        if bytes.len() > limits.max_head_bytes {
            return Err(CaptureError::HeadLimitExceeded);
        }
        let boundary = bytes
            .windows(4)
            .position(|unit| unit == b"\r\n\r\n")
            .ok_or(CaptureError::TruncatedHead)?;
        if boundary + 4 != bytes.len() {
            return Err(CaptureError::TrailingBytes);
        }
        if bytes.starts_with(b"\r\n") {
            return Err(CaptureError::EmptyInput);
        }
        let mut lines = Vec::new();
        let mut start = 0;
        while start < bytes.len() {
            let end = bytes[start..]
                .windows(2)
                .position(|pair| pair == b"\r\n")
                .map(|offset| start + offset)
                .ok_or(CaptureError::TruncatedHead)?;
            if end + 2 - start > limits.max_line_bytes {
                return Err(CaptureError::LineLimitExceeded { line: lines.len() });
            }
            let line = &bytes[start..end];
            if line.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
                return Err(CaptureError::InvalidLine { line: lines.len() });
            }
            if line.is_empty() {
                if end + 2 != bytes.len() {
                    return Err(CaptureError::TrailingBytes);
                }
                break;
            }
            if !lines.is_empty() && lines.len() > limits.max_headers {
                return Err(CaptureError::HeaderLimitExceeded);
            }
            lines.push(line);
            start = end + 2;
        }
        let request_line = lines.first().ok_or(CaptureError::EmptyInput)?;
        let first_space = request_line
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(CaptureError::InvalidRequestLine)?;
        let second_space = request_line[first_space + 1..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|offset| first_space + 1 + offset)
            .ok_or(CaptureError::InvalidRequestLine)?;
        if first_space == 0
            || second_space == first_space + 1
            || !request_line[..first_space].iter().all(|byte| token(*byte))
            || !request_line[first_space + 1..second_space]
                .iter()
                .all(|byte| (0x21..=0x7e).contains(byte))
            || !matches!(&request_line[second_space + 1..], b"HTTP/1.0" | b"HTTP/1.1")
        {
            return Err(CaptureError::InvalidRequestLine);
        }
        let mut headers = Vec::new();
        for (index, line) in lines.iter().skip(1).enumerate() {
            let colon = line
                .iter()
                .position(|byte| *byte == b':')
                .ok_or(CaptureError::InvalidLine { line: index + 1 })?;
            if colon == 0
                || !line[..colon].iter().all(|byte| token(*byte))
                || !line[colon + 1..]
                    .iter()
                    .all(|byte| *byte == b'\t' || *byte >= 0x20 && *byte != 0x7f)
            {
                return Err(CaptureError::InvalidLine { line: index + 1 });
            }
            headers.push(CapturedHeader {
                bytes: line.to_vec(),
                colon,
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            request_line: request_line.to_vec(),
            first_space,
            second_space,
            headers,
        })
    }

    /// Returns the full head, including CRLF delimiters.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Returns the exact request line without CRLF.
    #[must_use]
    pub fn request_line(&self) -> &[u8] {
        &self.request_line
    }
    /// Returns the method bytes.
    #[must_use]
    pub fn method(&self) -> &[u8] {
        &self.request_line[..self.first_space]
    }
    /// Returns the target bytes without interpreting or resolving them.
    #[must_use]
    pub fn target(&self) -> &[u8] {
        &self.request_line[self.first_space + 1..self.second_space]
    }
    /// Returns the HTTP version bytes.
    #[must_use]
    pub fn version(&self) -> &[u8] {
        &self.request_line[self.second_space + 1..]
    }
    /// Returns every header in wire order, including duplicate names.
    #[must_use]
    pub fn headers(&self) -> &[CapturedHeader] {
        &self.headers
    }
}

impl fmt::Debug for RequestHeadCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHeadCapture")
            .field("byte_count", &self.bytes.len())
            .field("header_count", &self.headers.len())
            .finish_non_exhaustive()
    }
}

/// A bounded capture or decoding failure. Formatting omits input bytes.
#[non_exhaustive]
pub enum CaptureError {
    /// No request bytes arrived.
    EmptyInput,
    /// Input ended before the final empty line.
    TruncatedHead,
    /// Bytes followed the final empty line during direct parsing.
    TrailingBytes,
    /// The request line had invalid method, target, or version syntax.
    InvalidRequestLine,
    /// A line had invalid syntax. Zero identifies the request line.
    InvalidLine {
        /// Zero-based line index.
        line: usize,
    },
    /// The total head-byte bound was reached.
    HeadLimitExceeded,
    /// A line exceeded its byte bound.
    LineLimitExceeded {
        /// Zero-based line index.
        line: usize,
    },
    /// The header-count bound was reached.
    HeaderLimitExceeded,
    /// The overall capture deadline elapsed.
    DeadlineExceeded,
    /// Reading the caller's stream failed.
    Io(io::Error),
}

impl fmt::Debug for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => f.write_str("HTTP/1 capture is empty"),
            Self::TruncatedHead => f.write_str("HTTP/1 head is truncated"),
            Self::TrailingBytes => f.write_str("bytes follow the HTTP/1 head"),
            Self::InvalidRequestLine => f.write_str("HTTP/1 request line is invalid"),
            Self::InvalidLine { line } => write!(f, "HTTP/1 line {line} is invalid"),
            Self::HeadLimitExceeded => f.write_str("HTTP/1 head exceeds its byte limit"),
            Self::LineLimitExceeded { line } => {
                write!(f, "HTTP/1 line {line} exceeds its byte limit")
            }
            Self::HeaderLimitExceeded => f.write_str("HTTP/1 head exceeds its header limit"),
            Self::DeadlineExceeded => f.write_str("HTTP/1 capture deadline exceeded"),
            Self::Io(_) => f.write_str("HTTP/1 capture read failed"),
        }
    }
}
impl Error for CaptureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// Reads one head within an overall deadline and explicit size bounds.
///
/// Single-byte reads leave every body byte in the caller's stream. You can
/// wrap that stream in a buffered reader. Cancellation may consume part of
/// the head, so discard the stream or restore a known boundary afterwards.
///
/// # Errors
///
/// Returns [`CaptureError`] for empty or truncated input, invalid head syntax,
/// a head, line, or header-count limit, a read failure, or an elapsed deadline.
/// An error may consume part or all of the head without restoring the reader.
///
/// # Panics
///
/// Panics when polled outside a Tokio runtime with its timer enabled, as
/// [`tokio::time::timeout_at`] does. Socket readers also need runtime I/O.
pub async fn capture_request_head<R>(
    reader: &mut R,
    deadline: Instant,
    limits: CaptureLimits,
) -> Result<RequestHeadCapture, CaptureError>
where
    R: AsyncRead + Unpin,
{
    timeout_at(deadline, async {
        let mut bytes = Vec::new();
        let mut line_bytes = 0;
        let mut completed_lines = 0;
        loop {
            if bytes.len() == limits.max_head_bytes {
                return Err(CaptureError::HeadLimitExceeded);
            }
            if line_bytes == limits.max_line_bytes {
                return Err(CaptureError::LineLimitExceeded {
                    line: completed_lines,
                });
            }
            let byte = match reader.read_u8().await {
                Ok(byte) => byte,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(if bytes.is_empty() {
                        CaptureError::EmptyInput
                    } else {
                        CaptureError::TruncatedHead
                    });
                }
                Err(error) => return Err(CaptureError::Io(error)),
            };
            bytes.push(byte);
            line_bytes += 1;
            if bytes.ends_with(b"\r\n\r\n") {
                return RequestHeadCapture::parse(&bytes, limits);
            }
            if bytes.ends_with(b"\r\n") {
                if completed_lines > limits.max_headers {
                    return Err(CaptureError::HeaderLimitExceeded);
                }
                completed_lines += 1;
                line_bytes = 0;
            }
        }
    })
    .await
    .map_err(|_| CaptureError::DeadlineExceeded)?
}

fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

#[cfg(test)]
mod tests;
