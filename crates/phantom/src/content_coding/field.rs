//! `Accept-Encoding` and `Content-Encoding` field grammar (RFC 9110 §8.4, §12.5.3).

use super::ContentCoding;

/// Most non-identity codings one response may stack.
pub(super) const MAXIMUM_STACKED_CODINGS: usize = 3;

/// Supported codings named by a caller's ordered `Accept-Encoding` fields.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AdvertisedContentCodings {
    gzip: bool,
    deflate: bool,
    brotli: bool,
    zstd: bool,
}

impl AdvertisedContentCodings {
    pub(super) const fn contains(self, coding: ContentCoding) -> bool {
        match coding {
            ContentCoding::Gzip => self.gzip,
            ContentCoding::Deflate => self.deflate,
            ContentCoding::Brotli => self.brotli,
            ContentCoding::Zstd => self.zstd,
        }
    }

    fn set(&mut self, coding: ContentCoding) {
        match coding {
            ContentCoding::Gzip => self.gzip = true,
            ContentCoding::Deflate => self.deflate = true,
            ContentCoding::Brotli => self.brotli = true,
            ContentCoding::Zstd => self.zstd = true,
        }
    }
}

/// Parses every `Accept-Encoding` field line in order as one list.
///
/// A coding is advertised by an explicit member with a nonzero weight, or by a
/// nonzero `*` when it has no explicit member. An explicit `q=0` always
/// withdraws the coding.
pub(super) fn parse_accept_encoding<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<AdvertisedContentCodings, &'static str> {
    let mut explicit = AdvertisedContentCodings::default();
    let mut withdrawn = AdvertisedContentCodings::default();
    let mut seen_identity = false;
    let mut wildcard = None;

    for value in values {
        let value =
            std::str::from_utf8(value).map_err(|_| "Accept-Encoding must contain visible ASCII")?;
        for member in value.split(',') {
            let member = trim_whitespace(member);
            if member.is_empty() {
                continue;
            }
            let (name, weight) = match member.split_once(';') {
                Some((name, parameters)) => (trim_whitespace(name), Some(parameters)),
                None => (member, None),
            };
            if !is_token(name) {
                return Err("Accept-Encoding member is not a token");
            }
            let nonzero = match weight {
                Some(parameters) => parse_weight(parameters)?,
                None => true,
            };

            if name == "*" {
                if wildcard.replace(nonzero).is_some() {
                    return Err("Accept-Encoding repeats a member");
                }
            } else if name.eq_ignore_ascii_case("identity") {
                if seen_identity {
                    return Err("Accept-Encoding repeats a member");
                }
                seen_identity = true;
            } else if let Some(coding) = ContentCoding::from_token(name) {
                if explicit.contains(coding) || withdrawn.contains(coding) {
                    return Err("Accept-Encoding repeats a member");
                }
                if nonzero {
                    explicit.set(coding);
                } else {
                    withdrawn.set(coding);
                }
            }
        }
    }

    let mut advertised = explicit;
    if wildcard == Some(true) {
        for coding in ContentCoding::ALL {
            if !withdrawn.contains(coding) {
                advertised.set(coding);
            }
        }
    }
    Ok(advertised)
}

/// Parsed response `Content-Encoding` list in application order.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum ContentEncodingList {
    /// Absent, empty, or identity-only: the body is passed through unchanged.
    Identity,
    /// One to [`MAXIMUM_STACKED_CODINGS`] supported codings in application order.
    Codings(Vec<ContentCoding>),
}

/// Parses every `Content-Encoding` field line in received order as one list.
pub(super) fn parse_content_encoding<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<ContentEncodingList, &'static str> {
    let mut codings = Vec::new();
    let mut identity = false;

    for value in values {
        if !value
            .iter()
            .all(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t'))
        {
            return Err("Content-Encoding must contain visible ASCII");
        }
        let value = std::str::from_utf8(value)
            .map_err(|_| "Content-Encoding must contain visible ASCII")?;
        for member in value.split(',') {
            let member = trim_whitespace(member);
            if member.is_empty() {
                continue;
            }
            if member.eq_ignore_ascii_case("identity") {
                identity = true;
                continue;
            }
            let coding = ContentCoding::from_token(member)
                .ok_or("response uses an unsupported content coding")?;
            if codings.len() == MAXIMUM_STACKED_CODINGS {
                return Err("response stacks too many content codings");
            }
            codings.push(coding);
        }
    }

    match (identity, codings.is_empty()) {
        (_, true) => Ok(ContentEncodingList::Identity),
        (true, false) => Err("response mixes identity with a content coding"),
        (false, false) => Ok(ContentEncodingList::Codings(codings)),
    }
}

/// Parses `OWS "q=" qvalue` and reports whether the weight is nonzero.
fn parse_weight(parameters: &str) -> Result<bool, &'static str> {
    let parameter = trim_whitespace(parameters);
    let Some(value) = parameter
        .strip_prefix("q=")
        .or_else(|| parameter.strip_prefix("Q="))
    else {
        return Err("Accept-Encoding permits only the q parameter");
    };
    let (integer, fraction) = match value.split_once('.') {
        Some((integer, fraction)) => (integer, Some(fraction)),
        None => (value, None),
    };
    let fraction = fraction.unwrap_or("");
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Accept-Encoding has a malformed qvalue");
    }
    match integer {
        "0" => Ok(fraction.bytes().any(|byte| byte != b'0')),
        "1" if fraction.bytes().all(|byte| byte == b'0') => Ok(true),
        _ => Err("Accept-Encoding has a malformed qvalue"),
    }
}

fn trim_whitespace(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t'))
}

/// RFC 9110 §5.6.2 `token`.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
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
                )
        })
}
