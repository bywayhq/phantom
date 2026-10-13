use super::{support::Incoming, *};
use crate::error::ProtocolError;
use std::io::Cursor;

fn reads_as_reserved_bits_error(frames: &[u8], deflate: bool) {
    let config = if deflate {
        WebSocketConfig::default().enable_deflate()
    } else {
        WebSocketConfig::default()
    };
    let mut socket = WebSocket::from_raw_socket(
        Incoming(Cursor::new(frames.to_vec())),
        Role::Client,
        Some(config),
    );
    assert!(
        matches!(
            socket.read().unwrap_err(),
            Error::Protocol(ProtocolError::NonZeroReservedBits)
        ),
        "RSV1 must be rejected here"
    );
}

#[test]
fn rsv1_without_a_negotiated_extension_is_rejected() {
    reads_as_reserved_bits_error(&[0x41, 0x03, 0xf2, 0x48, 0xcd], false);
}

#[test]
fn rsv1_on_a_control_frame_is_rejected() {
    reads_as_reserved_bits_error(&[0xc9, 0x00], true);
}

#[test]
fn rsv1_on_a_continuation_frame_is_rejected() {
    reads_as_reserved_bits_error(
        &[
            0x41, 0x03, 0xf2, 0x48, 0xcd, 0xc0, 0x04, 0xc9, 0xc9, 0x07, 0x00,
        ],
        true,
    );
}

#[test]
fn control_the_same_message_without_rsv1_on_the_continuation_decodes() {
    let mut socket = WebSocket::from_raw_socket(
        Incoming(Cursor::new(vec![
            0x41, 0x03, 0xf2, 0x48, 0xcd, 0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00,
        ])),
        Role::Client,
        Some(WebSocketConfig::default().enable_deflate()),
    );
    assert_eq!(
        socket.read().expect("a legal compressed message"),
        Message::text("Hello")
    );
}

#[test]
fn deflate_response_rejects_unicode_whitespace_in_parameter_names(
) -> Result<(), Box<dyn std::error::Error>> {
    for whitespace in ["\u{00a0}", "\u{0085}", "\u{2003}", "\u{202f}"] {
        for raw in [
            format!("permessage-deflate; {whitespace}server_no_context_takeover"),
            format!("permessage-deflate; server_no_context_takeover{whitespace}"),
            format!("permessage-deflate; server_max_window_bits{whitespace}=10"),
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "sec-websocket-extensions",
                http::HeaderValue::from_bytes(raw.as_bytes())?,
            );

            let result = WebSocketConfig::default()
                .enable_deflate()
                .accept_deflate_response(&headers);

            assert!(
                matches!(result, Err(Error::Protocol(ProtocolError::InvalidHeader(ref name)))
                    if name.as_str() == "sec-websocket-extensions"),
                "accepted non-HTTP whitespace in a parameter name: {raw:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn deflate_response_rejects_unicode_whitespace_around_window_values(
) -> Result<(), Box<dyn std::error::Error>> {
    for whitespace in ["\u{00a0}", "\u{0085}", "\u{2003}", "\u{202f}"] {
        for parameter in ["server_max_window_bits", "client_max_window_bits"] {
            for value in [
                format!("{whitespace}10"),
                format!("10{whitespace}"),
                format!("{whitespace}\"10\"{whitespace}"),
            ] {
                let raw = format!("permessage-deflate; {parameter}={value}");
                let mut headers = http::HeaderMap::new();
                headers.insert(
                    "sec-websocket-extensions",
                    http::HeaderValue::from_bytes(raw.as_bytes())?,
                );

                let result = WebSocketConfig::default()
                    .enable_deflate()
                    .accept_deflate_response(&headers);

                assert!(
                    matches!(result, Err(Error::Protocol(ProtocolError::InvalidHeader(ref name)))
                        if name.as_str() == "sec-websocket-extensions"),
                    "accepted non-HTTP whitespace around a window value: {raw:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn deflate_response_keeps_http_whitespace_and_quoted_window_values(
) -> Result<(), Box<dyn std::error::Error>> {
    for raw in [
        b"permessage-deflate; server_no_context_takeover; server_max_window_bits=10; client_max_window_bits=11".as_slice(),
        b" \tpermessage-deflate\t ;\tserver_no_context_takeover\t; server_max_window_bits\t=\t10\t; client_max_window_bits = 11 \t",
        b"permessage-deflate; server_no_context_takeover; server_max_window_bits=\"10\"; client_max_window_bits=\"11\"",
        b"permessage-deflate; server_no_context_takeover; server_max_window_bits=\"\\1\\0\"; client_max_window_bits=\"\\1\\1\"",
    ] {
        let mut headers = http::HeaderMap::new();
        headers.insert("sec-websocket-extensions", http::HeaderValue::from_bytes(raw)?);

        let config = WebSocketConfig::default().enable_deflate().accept_deflate_response(&headers)?;
        let selected = config.permessage_deflate().ok_or("valid response declined compression")?;

        assert!(selected.server_no_context_takeover());
        assert_eq!(selected.server_max_window_bits(), 10);
        assert_eq!(selected.client_max_window_bits(), 11);
    }
    Ok(())
}

#[test]
fn deflate_response_rejects_non_ascii_extension_names_and_quoted_digits(
) -> Result<(), Box<dyn std::error::Error>> {
    for raw in [
        "permessage-deflate; server_max_window_bits=\"\u{00a0}10\"",
        "permessage-deflate; server_max_window_bits=\"10\u{00a0}\"",
        "\u{00a0}permessage-deflate; server_max_window_bits=10",
    ] {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "sec-websocket-extensions",
            http::HeaderValue::from_bytes(raw.as_bytes())?,
        );

        let result = WebSocketConfig::default()
            .enable_deflate()
            .accept_deflate_response(&headers);

        assert!(
            matches!(result, Err(Error::Protocol(ProtocolError::InvalidHeader(ref name)))
            if name.as_str() == "sec-websocket-extensions")
        );
    }
    Ok(())
}

#[test]
fn deflate_server_skips_unrelated_extension_obs_text() -> Result<(), Box<dyn std::error::Error>> {
    let offers = [http::HeaderValue::from_bytes(
        b"x-other; value=\"\xff\xc2\xa0\", permessage-deflate",
    )?];

    let (config, response) = WebSocketConfig::default()
        .enable_deflate()
        .accept_deflate_offers(&offers);

    assert!(config.permessage_deflate().is_some());
    assert_eq!(
        response
            .ok_or("valid deflate offer was skipped")?
            .as_bytes(),
        b"permessage-deflate"
    );
    Ok(())
}
