use http::{
    HeaderMap, HeaderName, Version,
    header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING, UPGRADE},
};

use super::{ACCEPT_NAME, EXTENSIONS_NAME, PROTOCOL_NAME, is_token, split_tokens, trim_ows};
use crate::WebSocketError;

pub(in crate::websocket) fn validate_response(
    version: Version,
    headers: &HeaderMap,
    expected_accept: &str,
    offered_protocols: &[Box<str>],
    allow_extensions: bool,
) -> Result<Option<Box<str>>, WebSocketError> {
    if version != Version::HTTP_11 {
        return Err(WebSocketError::invalid_handshake(
            "WebSocket Upgrade response must use HTTP/1.1",
        ));
    }
    if headers.contains_key(CONTENT_LENGTH) || headers.contains_key(TRANSFER_ENCODING) {
        return Err(WebSocketError::invalid_handshake(
            "WebSocket 101 response must not contain HTTP body framing",
        ));
    }

    let upgrade = response_tokens(headers, &UPGRADE)?;
    if upgrade.len() != 1 || !upgrade[0].eq_ignore_ascii_case(b"websocket") {
        return Err(WebSocketError::invalid_handshake(
            "WebSocket 101 response has an invalid Upgrade field",
        ));
    }

    let connection = response_tokens(headers, &CONNECTION)?;
    if connection
        .iter()
        .filter(|token| token.eq_ignore_ascii_case(b"upgrade"))
        .count()
        != 1
    {
        return Err(WebSocketError::invalid_handshake(
            "WebSocket 101 response has an invalid Connection field",
        ));
    }

    let mut accept_values = headers.get_all(ACCEPT_NAME).iter();
    let accept = accept_values.next().ok_or_else(|| {
        WebSocketError::invalid_handshake("WebSocket 101 response is missing Sec-WebSocket-Accept")
    })?;
    if accept_values.next().is_some() || accept.as_bytes() != expected_accept.as_bytes() {
        return Err(WebSocketError::invalid_handshake(
            "WebSocket 101 response has an invalid Sec-WebSocket-Accept",
        ));
    }

    if !allow_extensions && headers.contains_key(EXTENSIONS_NAME) {
        return Err(WebSocketError::invalid_handshake(
            "server selected an unsupported WebSocket extension",
        ));
    }

    let mut selected_values = headers.get_all(PROTOCOL_NAME).iter();
    let Some(selected) = selected_values.next() else {
        return Ok(None);
    };
    if selected_values.next().is_some() {
        return Err(WebSocketError::invalid_handshake(
            "server returned multiple WebSocket subprotocol fields",
        ));
    }
    let selected = trim_ows(selected.as_bytes());
    if !is_token(selected) || selected.contains(&b',') {
        return Err(WebSocketError::invalid_handshake(
            "server returned an invalid WebSocket subprotocol",
        ));
    }
    let selected = std::str::from_utf8(selected).map_err(|_| {
        WebSocketError::invalid_handshake("server returned a non-ASCII WebSocket subprotocol")
    })?;
    if !offered_protocols
        .iter()
        .any(|offered| offered.as_ref() == selected)
    {
        return Err(WebSocketError::invalid_handshake(
            "server selected a WebSocket subprotocol that was not offered",
        ));
    }
    Ok(Some(selected.into()))
}

fn response_tokens<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Vec<&'a [u8]>, WebSocketError> {
    let mut tokens = Vec::new();
    for value in headers.get_all(name).iter() {
        tokens.extend(split_tokens(value.as_bytes()).map_err(|()| {
            WebSocketError::invalid_handshake(
                "WebSocket 101 response contains an invalid comma-separated token",
            )
        })?);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, Version};

    use super::validate_response;

    #[test]
    fn offered_protocol_may_remain_unselected() -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", "websocket".parse()?);
        headers.insert("connection", "keep-alive, Upgrade".parse()?);
        headers.insert("sec-websocket-accept", "expected".parse()?);

        assert_eq!(
            validate_response(
                Version::HTTP_11,
                &headers,
                "expected",
                &["chat".into()],
                false,
            )?,
            None
        );
        Ok(())
    }

    #[test]
    fn rejects_token_substrings_and_unsolicited_extensions()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", "websocket".parse()?);
        headers.insert("connection", "notupgrade".parse()?);
        headers.insert("sec-websocket-accept", "expected".parse()?);
        assert!(validate_response(Version::HTTP_11, &headers, "expected", &[], false).is_err());

        headers.insert("connection", "Upgrade".parse()?);
        headers.insert("sec-websocket-extensions", "permessage-deflate".parse()?);
        assert!(validate_response(Version::HTTP_11, &headers, "expected", &[], false).is_err());
        headers.remove("sec-websocket-extensions");
        assert!(validate_response(Version::HTTP_10, &headers, "expected", &[], false).is_err());
        Ok(())
    }
}
