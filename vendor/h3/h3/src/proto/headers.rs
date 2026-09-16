use std::{
    convert::TryFrom,
    fmt,
    iter::{IntoIterator, Iterator},
    str::FromStr,
};

use http::{
    header::{self, HeaderName, HeaderValue},
    uri::{self, Authority, Parts, PathAndQuery, Scheme, Uri},
    Extensions, HeaderMap, Method, StatusCode,
};

use crate::{
    ext::{OrderedHeaders, Protocol, RequestPseudoHeader, RequestPseudoHeaderOrder},
    qpack::HeaderField,
};

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub struct Header {
    pseudo: Pseudo,
    pseudo_order: Option<Vec<RequestPseudoHeader>>,
    fields: HeaderMap,
    ordered_fields: Option<Vec<(HeaderName, HeaderValue)>>,
}

#[allow(clippy::len_without_is_empty)]
impl Header {
    /// Creates a new `Header` frame data suitable for sending a request
    pub fn request(
        method: Method,
        uri: Uri,
        fields: HeaderMap,
        mut ext: Extensions,
    ) -> Result<Self, HeaderError> {
        let ordered_fields = ext.remove::<OrderedHeaders>();
        if ordered_fields
            .as_ref()
            .is_some_and(|ordered| !ordered.agrees_with(&fields))
        {
            return Err(HeaderError::ContradictedOrderedHeaders);
        }
        match (uri.authority(), fields.get("host")) {
            (None, None) => return Err(HeaderError::MissingAuthority),
            (Some(a), Some(h)) if a.as_str() != h => {
                return Err(HeaderError::ContradictedAuthority);
            }
            _ => {}
        }
        let pseudo_order = ext.remove::<RequestPseudoHeaderOrder>();
        let pseudo = Pseudo::request(method, uri, ext);
        if pseudo_order
            .as_ref()
            .is_some_and(|order| !pseudo.agrees_with(order.as_slice()))
        {
            return Err(HeaderError::InvalidPseudoHeaderOrder);
        }

        Ok(Self {
            pseudo,
            pseudo_order: pseudo_order.map(RequestPseudoHeaderOrder::into_inner),
            fields,
            ordered_fields: ordered_fields.map(OrderedHeaders::into_inner),
        })
    }

    pub fn response(status: StatusCode, fields: HeaderMap) -> Self {
        Self {
            pseudo: Pseudo::response(status),
            pseudo_order: None,
            fields,
            ordered_fields: None,
        }
    }

    pub fn trailer(fields: HeaderMap) -> Self {
        Self {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
            //# Pseudo-header fields MUST NOT appear in trailer
            //# sections.
            pseudo: Pseudo::default(),
            pseudo_order: None,
            fields,
            ordered_fields: None,
        }
    }

    pub fn into_request_parts(
        self,
    ) -> Result<(Method, Uri, Option<Protocol>, HeaderMap), HeaderError> {
        let mut uri = Uri::builder();

        if let Some(path) = self.pseudo.path {
            uri = uri.path_and_query(path.as_str().as_bytes());
        }

        if let Some(scheme) = self.pseudo.scheme {
            uri = uri.scheme(scheme.as_str().as_bytes());
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=TODO
        //# If the scheme does not have a mandatory authority component and none
        //# is provided in the request target, the request MUST NOT contain the
        //# :authority pseudo-header or Host header fields.
        match (self.pseudo.authority, self.fields.get("host")) {
            (None, None) => return Err(HeaderError::MissingAuthority),
            (Some(a), None) => uri = uri.authority(a.as_str().as_bytes()),
            (None, Some(h)) => uri = uri.authority(h.as_bytes()),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If both fields are present, they MUST contain the same value.
            (Some(a), Some(h)) if a.as_str() != h => {
                return Err(HeaderError::ContradictedAuthority);
            }
            (Some(_), Some(h)) => uri = uri.authority(h.as_bytes()),
        }

        Ok((
            self.pseudo.method.ok_or(HeaderError::MissingMethod)?,
            // When empty host field is built into an uri it fails
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            uri.build().map_err(HeaderError::InvalidRequest)?,
            self.pseudo.protocol,
            self.fields,
        ))
    }

    pub fn into_response_parts(
        self,
    ) -> Result<(StatusCode, HeaderMap, Option<OrderedHeaders>), HeaderError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.2
        //= type=implication
        //# For responses, a single ":status" pseudo-header field is defined that
        //# carries the HTTP status code; see Section 15 of [HTTP].  This pseudo-
        //# header field MUST be included in all responses; otherwise, the
        //# response is malformed (see Section 4.1.2).
        Ok((
            self.pseudo.status.ok_or(HeaderError::MissingStatus)?,
            self.fields,
            self.ordered_fields.map(OrderedHeaders::new),
        ))
    }

    pub fn into_fields(self) -> HeaderMap {
        self.fields
    }

    pub fn len(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    pub fn size(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    #[cfg(test)]
    pub(crate) fn authory_mut(&mut self) -> &mut Option<Authority> {
        &mut self.pseudo.authority
    }
}

impl IntoIterator for Header {
    type Item = HeaderField;
    type IntoIter = HeaderIter;
    fn into_iter(self) -> Self::IntoIter {
        HeaderIter {
            pseudo: Some(self.pseudo),
            pseudo_order: self.pseudo_order.map(Vec::into_iter),
            ordered_fields: self.ordered_fields.map(Vec::into_iter),
            last_header_name: None,
            fields: self.fields.into_iter(),
        }
    }
}

pub struct HeaderIter {
    pseudo: Option<Pseudo>,
    pseudo_order: Option<std::vec::IntoIter<RequestPseudoHeader>>,
    ordered_fields: Option<std::vec::IntoIter<(HeaderName, HeaderValue)>>,
    last_header_name: Option<HeaderName>,
    fields: header::IntoIter<HeaderValue>,
}

impl Iterator for HeaderIter {
    type Item = HeaderField;

    fn next(&mut self) -> Option<Self::Item> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# All pseudo-header fields MUST appear in the header section before
        //# regular header fields.
        if let Some(order) = self.pseudo_order.as_mut() {
            if let Some(header) = order.next() {
                let pseudo = self.pseudo.as_mut()?;
                return Some(match header {
                    RequestPseudoHeader::Method => {
                        (":method", pseudo.method.take()?.as_str()).into()
                    }
                    RequestPseudoHeader::Authority => {
                        (":authority", pseudo.authority.take()?.as_str().as_bytes()).into()
                    }
                    RequestPseudoHeader::Scheme => {
                        (":scheme", pseudo.scheme.take()?.as_str().as_bytes()).into()
                    }
                    RequestPseudoHeader::Path => {
                        (":path", pseudo.path.take()?.as_str().as_bytes()).into()
                    }
                    RequestPseudoHeader::Protocol => {
                        (":protocol", pseudo.protocol.take()?.as_str().as_bytes()).into()
                    }
                });
            }
            self.pseudo = None;
        }

        if let Some(ref mut pseudo) = self.pseudo {
            if let Some(method) = pseudo.method.take() {
                return Some((":method", method.as_str()).into());
            }

            if let Some(scheme) = pseudo.scheme.take() {
                return Some((":scheme", scheme.as_str().as_bytes()).into());
            }

            if let Some(authority) = pseudo.authority.take() {
                return Some((":authority", authority.as_str().as_bytes()).into());
            }

            if let Some(path) = pseudo.path.take() {
                return Some((":path", path.as_str().as_bytes()).into());
            }

            if let Some(status) = pseudo.status.take() {
                return Some((":status", status.as_str()).into());
            }

            if let Some(protocol) = pseudo.protocol.take() {
                return Some((":protocol", protocol.as_str().as_bytes()).into());
            }
        }

        self.pseudo = None;

        if let Some(ordered) = self.ordered_fields.as_mut() {
            return ordered.next().map(|(name, value)| {
                let sensitive = value.is_sensitive();
                HeaderField::from((name.as_str(), value.as_bytes())).with_sensitive(sensitive)
            });
        }

        for (new_header_name, header_value) in self.fields.by_ref() {
            if let Some(new) = new_header_name {
                self.last_header_name = Some(new);
            }
            if let (Some(ref n), v) = (&self.last_header_name, header_value) {
                let sensitive = v.is_sensitive();
                return Some(
                    HeaderField::from((n.as_str(), v.as_bytes())).with_sensitive(sensitive),
                );
            }
        }

        None
    }
}

impl TryFrom<Vec<HeaderField>> for Header {
    type Error = HeaderError;
    fn try_from(headers: Vec<HeaderField>) -> Result<Self, Self::Error> {
        let mut fields = HeaderMap::with_capacity(headers.len());
        let mut ordered_fields = Vec::with_capacity(headers.len());
        let mut pseudo = Pseudo::default();
        let mut regular_field_seen = false;

        for field in headers.into_iter() {
            let (name, value, sensitive) = field.into_parts();
            match Field::parse(name, value)? {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
                //# Any request or response that contains a
                //# pseudo-header field that appears in a header section after a regular
                //# header field MUST be treated as malformed.
                Field::Method(_)
                | Field::Scheme(_)
                | Field::Authority(_)
                | Field::Path(_)
                | Field::Status(_)
                | Field::Protocol(_)
                    if regular_field_seen =>
                {
                    return Err(HeaderError::PseudoAfterRegularField);
                }
                Field::Method(m) => {
                    pseudo.method = Some(m);
                    pseudo.len += 1;
                }
                Field::Scheme(s) => {
                    pseudo.scheme = Some(s);
                    pseudo.len += 1;
                }
                Field::Authority(a) => {
                    pseudo.authority = Some(a);
                    pseudo.len += 1;
                }
                Field::Path(p) => {
                    pseudo.path = Some(p);
                    pseudo.len += 1;
                }
                Field::Status(s) => {
                    pseudo.status = Some(s);
                    pseudo.len += 1;
                }
                Field::Header((n, mut v)) => {
                    regular_field_seen = true;
                    v.set_sensitive(sensitive);
                    ordered_fields.push((n.clone(), v.clone()));
                    fields.append(n, v);
                }
                Field::Protocol(p) => {
                    pseudo.protocol = Some(p);
                    pseudo.len += 1;
                }
            }
        }

        Ok(Header {
            pseudo,
            pseudo_order: None,
            fields,
            ordered_fields: Some(ordered_fields),
        })
    }
}

enum Field {
    Method(Method),
    Scheme(Scheme),
    Authority(Authority),
    Path(PathAndQuery),
    Status(StatusCode),
    Protocol(Protocol),
    Header((HeaderName, HeaderValue)),
}

impl Field {
    fn parse<N, V>(name: N, value: V) -> Result<Self, HeaderError>
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let name = name.as_ref();
        if name.is_empty() {
            return Err(HeaderError::InvalidHeaderName("name is empty".into()));
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Requests or responses containing invalid field names MUST be treated
        //# as malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Any request or response that contains a
        //# character not permitted in a field value MUST be treated as
        //# malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=implication
        //# A request or
        //# response containing uppercase characters in field names MUST be
        //# treated as malformed.

        if name[0] != b':' {
            return Ok(Field::Header((
                HeaderName::from_lowercase(name).map_err(|_| HeaderError::invalid_name(name))?,
                HeaderValue::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            )));
        }

        Ok(match name {
            b":scheme" => Field::Scheme(try_value(name, value)?),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            b":authority" => Field::Authority(try_value(name, value)?),
            b":path" => Field::Path(try_value(name, value)?),
            b":method" => Field::Method(
                Method::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":status" => Field::Status(
                StatusCode::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":protocol" => Field::Protocol(try_value(name, value)?),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
            //# Endpoints MUST treat a request or response that contains
            //# undefined or invalid pseudo-header fields as malformed.
            _ => return Err(HeaderError::invalid_name(name)),
        })
    }
}

fn try_value<N, V, R>(name: N, value: V) -> Result<R, HeaderError>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
    R: FromStr,
{
    let (name, value) = (name.as_ref(), value.as_ref());
    let s = std::str::from_utf8(value).map_err(|_| HeaderError::invalid_value(name, value))?;
    R::from_str(s).map_err(|_| HeaderError::invalid_value(name, value))
}

/// Pseudo-header fields have the same purpose as data from the first line of HTTP/1.X,
/// but are conveyed along with other headers. For example ':method' and ':path' in a
/// request, and ':status' in a response. They must be placed before all other fields,
/// start with ':', and be lowercase.
/// See RFC7540 section 8.1.2.1. for more details.
#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Clone))]
struct Pseudo {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //= type=implication
    //# Endpoints MUST NOT
    //# generate pseudo-header fields other than those defined in this
    //# document.

    // Request
    method: Option<Method>,
    scheme: Option<Scheme>,
    authority: Option<Authority>,
    path: Option<PathAndQuery>,

    // Response
    status: Option<StatusCode>,

    protocol: Option<Protocol>,

    len: usize,
}

#[allow(clippy::len_without_is_empty)]
impl Pseudo {
    fn request(method: Method, uri: Uri, ext: Extensions) -> Self {
        let Parts {
            scheme,
            authority,
            path_and_query,
            ..
        } = uri::Parts::from(uri);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# This pseudo-header field MUST NOT be empty for "http" or "https"
        //# URIs; "http" or "https" URIs that do not contain a path component
        //# MUST include a value of / (ASCII 0x2f).
        let path = path_and_query.map_or_else(
            || PathAndQuery::from_static("/"),
            |path| {
                if path.path().is_empty() && method != Method::OPTIONS {
                    PathAndQuery::from_static("/")
                } else {
                    path
                }
            },
        );

        // If the method is connect, the `:protocol` pseudo-header MAY be defined
        //
        // See: [https://www.rfc-editor.org/rfc/rfc8441#section-4]
        let protocol = if method == Method::CONNECT {
            ext.get::<Protocol>().copied()
        } else {
            None
        };

        // For standard CONNECT (that is, without :protocol pseudo-header) scheme and path
        // are not set. See: [https://www.rfc-editor.org/rfc/rfc9114#section-4.4]
        let (scheme, path) = if method == Method::CONNECT && protocol.is_none() {
            (None, None)
        } else {
            (scheme.or(Some(Scheme::HTTPS)), Some(path))
        };

        let len = 3 + authority.is_some() as usize + protocol.is_some() as usize;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# All HTTP/3 requests MUST include exactly one value for the :method,
        //# :scheme, and :path pseudo-header fields, unless the request is a
        //# CONNECT request; see Section 4.4.
        Self {
            method: Some(method),
            scheme,
            authority,
            path,
            status: None,
            protocol,
            len,
        }
    }

    fn response(status: StatusCode) -> Self {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.
        Pseudo {
            method: None,
            scheme: None,
            authority: None,
            path: None,
            status: Some(status),
            len: 1,
            protocol: None,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn agrees_with(&self, order: &[RequestPseudoHeader]) -> bool {
        let expected = usize::from(self.method.is_some())
            + usize::from(self.authority.is_some())
            + usize::from(self.scheme.is_some())
            + usize::from(self.path.is_some())
            + usize::from(self.protocol.is_some());
        if order.len() != expected {
            return false;
        }

        let mut seen = [false; 5];
        for header in order {
            let (index, present) = match header {
                RequestPseudoHeader::Method => (0, self.method.is_some()),
                RequestPseudoHeader::Authority => (1, self.authority.is_some()),
                RequestPseudoHeader::Scheme => (2, self.scheme.is_some()),
                RequestPseudoHeader::Path => (3, self.path.is_some()),
                RequestPseudoHeader::Protocol => (4, self.protocol.is_some()),
            };
            if !present || seen[index] {
                return false;
            }
            seen[index] = true;
        }
        true
    }
}

#[derive(Debug)]
pub enum HeaderError {
    InvalidHeaderName(String),
    InvalidHeaderValue(String),
    InvalidRequest(http::Error),
    MissingMethod,
    MissingStatus,
    MissingAuthority,
    ContradictedAuthority,
    ContradictedOrderedHeaders,
    InvalidPseudoHeaderOrder,
    PseudoAfterRegularField,
}

impl HeaderError {
    fn invalid_name<N>(name: N) -> Self
    where
        N: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderName(format!("{:?}", name.as_ref()))
    }

    fn invalid_value<N, V>(name: N, value: V) -> Self
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderValue(format!(
            "{:?} {:?}",
            String::from_utf8_lossy(name.as_ref()),
            value.as_ref()
        ))
    }
}

impl std::error::Error for HeaderError {}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::InvalidHeaderName(h) => write!(f, "invalid header name: {}", h),
            HeaderError::InvalidHeaderValue(v) => write!(f, "invalid header value: {}", v),
            HeaderError::InvalidRequest(r) => write!(f, "invalid request: {}", r),
            HeaderError::MissingMethod => write!(f, "missing method in request headers"),
            HeaderError::MissingStatus => write!(f, "missing status in response headers"),
            HeaderError::MissingAuthority => write!(f, "missing authority"),
            HeaderError::ContradictedAuthority => {
                write!(f, "uri and authority field are in contradiction")
            }
            HeaderError::ContradictedOrderedHeaders => {
                write!(f, "ordered fields disagree with semantic headers")
            }
            HeaderError::InvalidPseudoHeaderOrder => {
                write!(f, "pseudo-header order does not match the request")
            }
            HeaderError::PseudoAfterRegularField => {
                write!(
                    f,
                    "pseudo-header field appears after a regular header field"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use bytes::BytesMut;

    fn ordered_request() -> Result<Header, HeaderError> {
        let mut fields = HeaderMap::new();
        fields.append("x-repeat", HeaderValue::from_static("alpha"));
        fields.append("x-repeat", HeaderValue::from_static("beta"));
        fields.insert("x-middle", HeaderValue::from_static("between"));

        let ordered = vec![
            (
                HeaderName::from_static("x-repeat"),
                HeaderValue::from_static("alpha"),
            ),
            (
                HeaderName::from_static("x-middle"),
                HeaderValue::from_static("between"),
            ),
            (
                HeaderName::from_static("x-repeat"),
                HeaderValue::from_static("beta"),
            ),
        ];
        let mut extensions = Extensions::new();
        extensions.insert(OrderedHeaders::new(ordered));
        extensions.insert(RequestPseudoHeaderOrder::new(vec![
            RequestPseudoHeader::Method,
            RequestPseudoHeader::Authority,
            RequestPseudoHeader::Scheme,
            RequestPseudoHeader::Path,
        ]));

        Header::request(
            Method::GET,
            Uri::from_static("https://example.test/ordered"),
            fields,
            extensions,
        )
    }

    #[test]
    fn ordered_request_fields_reach_qpack_in_declared_order() {
        let header = ordered_request().expect("matching order must be accepted");
        let fields = header.clone().into_iter().collect::<Vec<_>>();
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.name.as_ref(), field.value.as_ref()))
                .collect::<Vec<_>>(),
            [
                (b":method".as_slice(), b"GET".as_slice()),
                (b":authority".as_slice(), b"example.test".as_slice()),
                (b":scheme".as_slice(), b"https".as_slice()),
                (b":path".as_slice(), b"/ordered".as_slice()),
                (b"x-repeat".as_slice(), b"alpha".as_slice()),
                (b"x-middle".as_slice(), b"between".as_slice()),
                (b"x-repeat".as_slice(), b"beta".as_slice()),
            ]
        );

        let mut block = BytesMut::new();
        crate::qpack::encode_stateless(&mut block, header).expect("ordered fields must encode");
        assert_eq!(
            block.as_ref(),
            &[
                0x00, 0x00, 0xd1, 0x50, 0x89, 0x2f, 0x91, 0xd3, 0x5d, 0x05, 0x5d, 0x25, 0x42, 0x7f,
                0xd7, 0x51, 0x86, 0x60, 0xf6, 0x48, 0x5b, 0x0b, 0x27, 0x2e, 0xf2, 0xb5, 0x85, 0xac,
                0xa3, 0x4f, 0x84, 0x1d, 0x15, 0xce, 0x3f, 0x2e, 0xf2, 0xb5, 0x26, 0x92, 0x4a, 0x0b,
                0x85, 0x8c, 0xa9, 0xf0, 0x52, 0xd5, 0x2e, 0xf2, 0xb5, 0x85, 0xac, 0xa3, 0x4f, 0x83,
                0x8c, 0xa9, 0x1f,
            ]
        );
    }

    #[test]
    fn request_without_order_extensions_preserves_upstream_encoding() {
        let mut fields = HeaderMap::new();
        fields.append("x-repeat", HeaderValue::from_static("alpha"));
        fields.append("x-repeat", HeaderValue::from_static("beta"));
        fields.insert("x-middle", HeaderValue::from_static("between"));
        let header = Header::request(
            Method::GET,
            Uri::from_static("https://example.test/ordered"),
            fields,
            Extensions::new(),
        )
        .expect("ordinary request must remain valid");
        let emitted = header.clone().into_iter().collect::<Vec<_>>();
        assert_eq!(
            emitted
                .iter()
                .map(|field| (field.name.as_ref(), field.value.as_ref()))
                .collect::<Vec<_>>(),
            [
                (b":method".as_slice(), b"GET".as_slice()),
                (b":scheme".as_slice(), b"https".as_slice()),
                (b":authority".as_slice(), b"example.test".as_slice()),
                (b":path".as_slice(), b"/ordered".as_slice()),
                (b"x-repeat".as_slice(), b"alpha".as_slice()),
                (b"x-repeat".as_slice(), b"beta".as_slice()),
                (b"x-middle".as_slice(), b"between".as_slice()),
            ]
        );

        let mut block = BytesMut::new();
        crate::qpack::encode_stateless(&mut block, header).expect("ordinary fields must encode");
        assert_eq!(
            block.as_ref(),
            &[
                0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x2f, 0x91, 0xd3, 0x5d, 0x05, 0x5d, 0x25, 0x42,
                0x7f, 0x51, 0x86, 0x60, 0xf6, 0x48, 0x5b, 0x0b, 0x27, 0x2e, 0xf2, 0xb5, 0x85, 0xac,
                0xa3, 0x4f, 0x84, 0x1d, 0x15, 0xce, 0x3f, 0x2e, 0xf2, 0xb5, 0x85, 0xac, 0xa3, 0x4f,
                0x83, 0x8c, 0xa9, 0x1f, 0x2e, 0xf2, 0xb5, 0x26, 0x92, 0x4a, 0x0b, 0x85, 0x8c, 0xa9,
                0xf0, 0x52, 0xd5,
            ]
        );
    }

    #[test]
    fn rejects_order_metadata_that_disagrees_with_request() {
        let mut fields = HeaderMap::new();
        fields.insert("x-field", HeaderValue::from_static("semantic"));
        let mut extensions = Extensions::new();
        extensions.insert(OrderedHeaders::new(vec![(
            HeaderName::from_static("x-field"),
            HeaderValue::from_static("different"),
        )]));
        assert_matches!(
            Header::request(
                Method::GET,
                Uri::from_static("https://example.test/"),
                fields,
                extensions,
            ),
            Err(HeaderError::ContradictedOrderedHeaders)
        );

        let mut fields = HeaderMap::new();
        let mut sensitive = HeaderValue::from_static("same");
        sensitive.set_sensitive(true);
        fields.insert("x-field", sensitive);
        let mut extensions = Extensions::new();
        extensions.insert(OrderedHeaders::new(vec![(
            HeaderName::from_static("x-field"),
            HeaderValue::from_static("same"),
        )]));
        assert_matches!(
            Header::request(
                Method::GET,
                Uri::from_static("https://example.test/"),
                fields,
                extensions,
            ),
            Err(HeaderError::ContradictedOrderedHeaders)
        );

        let mut extensions = Extensions::new();
        extensions.insert(RequestPseudoHeaderOrder::new(vec![
            RequestPseudoHeader::Method,
            RequestPseudoHeader::Method,
            RequestPseudoHeader::Scheme,
            RequestPseudoHeader::Path,
        ]));
        assert_matches!(
            Header::request(
                Method::GET,
                Uri::from_static("https://example.test/"),
                HeaderMap::new(),
                extensions,
            ),
            Err(HeaderError::InvalidPseudoHeaderOrder)
        );
    }

    #[test]
    fn request_has_no_authority_nor_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![(b":method", Method::GET.as_str()).into()]).unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::MissingAuthority)
        );
    }

    #[test]
    fn request_has_empty_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        assert_matches!(
            Header::try_from(vec![
                (b":method", Method::GET.as_str()).into(),
                (b":authority", b"").into(),
            ]),
            Err(HeaderError::InvalidHeaderValue(_))
        );
    }

    #[test]
    fn request_has_empty_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::InvalidRequest(_))
        );
    }

    #[test]
    fn request_has_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_same_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }
    #[test]
    fn request_has_different_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"authority.com").into(),
            (b"host", b"host.com").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::ContradictedAuthority)
        );
    }

    #[test]
    fn preserves_duplicate_headers() {
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"set-cookie", b"foo=foo").into(),
            (b"set-cookie", b"bar=bar").into(),
            (b"other-header", b"other-header-value").into(),
        ])
        .unwrap();

        assert_eq!(
            headers
                .clone()
                .into_iter()
                .filter(|h| h.name.as_ref() == b"set-cookie")
                .collect::<Vec<_>>(),
            vec![
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"foo=foo"),
                    sensitive: false,
                },
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"bar=bar"),
                    sensitive: false,
                }
            ]
        );
        assert_eq!(
            headers
                .into_iter()
                .filter(|h| h.name.as_ref() == b"other-header")
                .collect::<Vec<_>>(),
            vec![HeaderField {
                name: std::borrow::Cow::Borrowed(b"other-header"),
                value: std::borrow::Cow::Borrowed(b"other-header-value"),
                sensitive: false,
            },]
        );
    }

    #[test]
    fn preserves_sensitive_markers_in_both_directions() {
        let mut value = HeaderValue::from_static("secret");
        value.set_sensitive(true);

        let mut fields = HeaderMap::new();
        fields.insert("authorization", value.clone());
        let header = Header::request(
            Method::GET,
            Uri::from_static("https://example.test/"),
            fields,
            Extensions::new(),
        )
        .unwrap();
        let encoded = header
            .into_iter()
            .find(|field| field.name.as_ref() == b"authorization")
            .unwrap();
        assert!(encoded.sensitive);

        let decoded = Header::try_from(vec![
            HeaderField::new(":status", "200"),
            HeaderField::new("authorization", "secret").with_sensitive(true),
        ])
        .unwrap();
        assert!(decoded.into_fields()["authorization"].is_sensitive());

        let mut fields = HeaderMap::new();
        fields.insert("authorization", value.clone());
        let mut extensions = Extensions::new();
        extensions.insert(OrderedHeaders::new(vec![(
            HeaderName::from_static("authorization"),
            value,
        )]));
        let ordered = Header::request(
            Method::GET,
            Uri::from_static("https://example.test/"),
            fields,
            extensions,
        )
        .unwrap()
        .into_iter()
        .find(|field| field.name.as_ref() == b"authorization")
        .unwrap();
        assert!(ordered.sensitive);
    }

    #[test]
    fn decoded_response_retains_global_field_order_and_duplicates() {
        let decoded = Header::try_from(vec![
            HeaderField::new(":status", "200"),
            HeaderField::new("set-cookie", "first=1"),
            HeaderField::new("x-middle", "value"),
            HeaderField::new("set-cookie", "second=2"),
        ])
        .unwrap();
        let (_, _, ordered) = decoded.into_response_parts().unwrap();
        let ordered = ordered.unwrap();
        let observed = ordered
            .as_slice()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect::<Vec<_>>();

        assert_eq!(
            observed,
            [
                ("set-cookie", b"first=1".as_slice()),
                ("x-middle", b"value".as_slice()),
                ("set-cookie", b"second=2".as_slice()),
            ]
        );
    }

    #[test]
    fn rejects_undefined_pseudo_header() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=test
        //# Endpoints MUST treat a request or response that contains
        //# undefined or invalid pseudo-header fields as malformed.
        assert_matches!(
            Header::try_from(vec![(b":unknown", b"value").into()]),
            Err(HeaderError::InvalidHeaderName(_))
        );
    }

    #[test]
    fn rejects_pseudo_header_after_regular_header() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=test
        //# Any request or response that contains a
        //# pseudo-header field that appears in a header section after a regular
        //# header field MUST be treated as malformed.
        assert_matches!(
            Header::try_from(vec![
                (b"regular", b"value").into(),
                (b":method", b"GET").into(),
            ]),
            Err(HeaderError::PseudoAfterRegularField)
        );
    }
}
