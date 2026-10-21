use http::{HeaderMap, Method, StatusCode, header::CONTENT_LENGTH};

use super::{Http3Error, Http3ErrorKind};

/// Encoded DATA accounting; HEAD and 304 lengths describe a representation.
pub(in super::super) struct ResponseFraming {
    remaining: Option<u64>,
}

impl ResponseFraming {
    pub(in super::super) fn new(
        method: &Method,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Result<Self, Http3Error> {
        let length = content_length(headers)?;
        if length.is_some() && (status.is_informational() || status == StatusCode::NO_CONTENT) {
            return Err(invalid("HTTP/3 response status forbids content-length"));
        }
        if status == StatusCode::RESET_CONTENT && length.is_some_and(|length| length != 0) {
            return Err(invalid("HTTP/3 reset-content response declares content"));
        }
        let bodyless = method == Method::HEAD
            || status.is_informational()
            || matches!(
                status,
                StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
            );
        Ok(Self {
            remaining: if bodyless { Some(0) } else { length },
        })
    }

    pub(super) fn data(&mut self, bytes: usize) -> Result<(), Http3Error> {
        if let Some(remaining) = self.remaining.as_mut() {
            let bytes = u64::try_from(bytes)
                .map_err(|_| invalid("HTTP/3 response DATA exceeds its declared length"))?;
            *remaining = remaining
                .checked_sub(bytes)
                .ok_or_else(|| invalid("HTTP/3 response DATA exceeds its declared length"))?;
        }
        Ok(())
    }

    pub(super) fn finish(&self) -> Result<(), Http3Error> {
        if self.remaining.is_some_and(|remaining| remaining != 0) {
            return Err(invalid("HTTP/3 response ended before its declared length"));
        }
        Ok(())
    }
}

fn content_length(headers: &HeaderMap) -> Result<Option<u64>, Http3Error> {
    let mut length = None;
    for field in headers.get_all(CONTENT_LENGTH) {
        // RFC 9110 section 8.6 permits recovery only when all list values agree.
        for value in field.as_bytes().split(|byte| *byte == b',') {
            let value = value.trim_ascii();
            if value.is_empty() {
                return Err(invalid("HTTP/3 response content-length is invalid"));
            }
            let mut parsed = 0u64;
            for byte in value {
                if !byte.is_ascii_digit() {
                    return Err(invalid("HTTP/3 response content-length is invalid"));
                }
                parsed = parsed
                    .checked_mul(10)
                    .and_then(|number| number.checked_add(u64::from(byte - b'0')))
                    .ok_or_else(|| invalid("HTTP/3 response content-length is too large"))?;
            }
            if length.is_some_and(|length| length != parsed) {
                return Err(invalid("HTTP/3 response content-length values disagree"));
            }
            length = Some(parsed);
        }
    }
    Ok(length)
}

fn invalid(message: &'static str) -> Http3Error {
    Http3Error::without_source(Http3ErrorKind::Protocol, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn headers(values: &[&[u8]]) -> Result<HeaderMap, http::header::InvalidHeaderValue> {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(CONTENT_LENGTH, HeaderValue::from_bytes(value)?);
        }
        Ok(headers)
    }

    #[test]
    fn identical_lengths_and_full_u64_range_are_supported() -> TestResult {
        for (values, expected) in [
            (vec![], None),
            (vec![b"0".as_slice()], Some(0)),
            (vec![b"18446744073709551615".as_slice()], Some(u64::MAX)),
            (vec![b"1".as_slice(), b"01"], Some(1)),
            (vec![b" 1,\t01 ".as_slice()], Some(1)),
        ] {
            assert_eq!(content_length(&headers(&values)?)?, expected);
        }
        Ok(())
    }

    #[test]
    fn invalid_or_conflicting_lengths_are_protocol_failures() -> TestResult {
        for values in [
            vec![b"".as_slice()],
            vec![b" ".as_slice()],
            vec![b"+1".as_slice()],
            vec![b"-1".as_slice()],
            vec![b"1,".as_slice()],
            vec![b"1,2".as_slice()],
            vec![b"1".as_slice(), b"2"],
            vec![b"18446744073709551616".as_slice()],
            vec![b"\xff".as_slice()],
        ] {
            let error = content_length(&headers(&values)?)
                .err()
                .ok_or("invalid length accepted")?;
            assert_eq!(error.kind(), Http3ErrorKind::Protocol);
        }
        Ok(())
    }

    #[test]
    fn declared_length_counts_data_incrementally_before_success() -> TestResult {
        let mut framing = ResponseFraming::new(&Method::GET, StatusCode::OK, &headers(&[b"2"])?)?;
        assert!(framing.finish().is_err());
        framing.data(1)?;
        assert!(framing.finish().is_err());
        framing.data(1)?;
        framing.finish()?;
        assert!(framing.data(1).is_err());
        Ok(())
    }

    #[test]
    fn bodyless_lengths_describe_metadata_and_never_allow_data() -> TestResult {
        for (method, status) in [
            (Method::HEAD, StatusCode::OK),
            (Method::GET, StatusCode::NOT_MODIFIED),
        ] {
            let mut framing = ResponseFraming::new(&method, status, &headers(&[b"123"])?)?;
            framing.finish()?;
            framing.data(0)?;
            assert!(framing.data(1).is_err());
        }
        for status in [StatusCode::CONTINUE, StatusCode::NO_CONTENT] {
            assert!(ResponseFraming::new(&Method::GET, status, &headers(&[b"0"])?).is_err());
        }
        assert!(
            ResponseFraming::new(&Method::GET, StatusCode::RESET_CONTENT, &headers(&[b"1"])?)
                .is_err()
        );
        Ok(())
    }
}
