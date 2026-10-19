use super::*;
use phantom_profile::{ClientProfile, browser::chrome};

type TestResult = Result<(), Box<dyn Error>>;

fn client() -> Result<Client, crate::BuildError> {
    Client::builder(ClientProfile::new(chrome::v154_tcp_tls())).build()
}

fn rejected(client: &Client, uri: &str, raw: &[u8], kind: RawRequestErrorKind) {
    let Err(error) = import(client, uri, raw, raw.len()) else {
        panic!("invalid import accepted");
    };
    assert_eq!(error.kind(), kind);
    assert!(error.source().is_none());
}

#[test]
fn framing_rejects_ambiguous_lengths_extra_bytes_and_unsupported_fields() -> TestResult {
    use RawRequestErrorKind as Kind;
    let client = client()?;
    for (fields, body, kind) in [
        (
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            "",
            Kind::InvalidContentLength,
        ),
        ("Content-Length: 0, 0\r\n", "", Kind::InvalidContentLength),
        ("Content-Length: +0\r\n", "", Kind::InvalidContentLength),
        ("Content-Length: 00\r\n", "", Kind::InvalidContentLength),
        ("Content-Length: -1\r\n", "", Kind::InvalidContentLength),
        ("Content-Length:\r\n", "", Kind::InvalidContentLength),
        (
            "Content-Length: 999999999999999999999999999999\r\n",
            "",
            Kind::InvalidContentLength,
        ),
        ("Content-Length: 1\r\n", "", Kind::BodyLengthMismatch),
        ("Content-Length: 0\r\n", "x", Kind::BodyLengthMismatch),
        ("", "x", Kind::BodyLengthMismatch),
        (
            "Content-Length: 0\r\n",
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            Kind::BodyLengthMismatch,
        ),
        (
            "Transfer-Encoding: chunked\r\n",
            "0\r\n\r\n",
            Kind::UnsupportedHeader,
        ),
        (
            "Content-Length: 0\r\nTransfer-Encoding: identity\r\n",
            "",
            Kind::UnsupportedHeader,
        ),
        ("Trailer: X-End\r\n", "", Kind::UnsupportedHeader),
        ("Upgrade: websocket\r\n", "", Kind::UnsupportedHeader),
        (
            "Connection: keep-alive, UpGrAdE\r\n",
            "",
            Kind::UnsupportedHeader,
        ),
        (
            "Proxy-Authorization: Basic secret\r\n",
            "",
            Kind::UnsupportedHeader,
        ),
    ] {
        let raw = format!("POST / HTTP/1.1\r\nHost: example.com\r\n{fields}\r\n{body}");
        rejected(&client, "https://example.com/", raw.as_bytes(), kind);
    }
    Ok(())
}

#[test]
fn syntax_rejects_lf_folds_whitespace_in_names_and_incomplete_messages() -> TestResult {
    let client = client()?;
    for raw in [
        b"GET / HTTP/1.1\nHost: example.com\n\n".as_slice(),
        b"\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\nX-A: b\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n folded\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\nX-A: \0\r\n\r\n",
        b"GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n",
        b"",
    ] {
        rejected(
            &client,
            "https://example.com/",
            raw,
            RawRequestErrorKind::InvalidSyntax,
        );
    }
    for version in ["HTTP/1.0", "HTTP/2.0"] {
        let raw = format!("GET / {version}\r\nHost: example.com\r\n\r\n");
        rejected(
            &client,
            "https://example.com/",
            raw.as_bytes(),
            RawRequestErrorKind::UnsupportedVersion,
        );
    }
    Ok(())
}

#[test]
fn destination_never_uses_a_base_url_or_retargets_input() -> TestResult {
    let client = Client::builder(ClientProfile::new(chrome::v154_tcp_tls()))
        .base_url("https://example.com/")?
        .build()?;
    let raw = b"GET /a/%2e%2e/b?x=%2f HTTP/1.1\r\nHost: example.com\r\n\r\n";
    for uri in [
        "/a/%2e%2e/b?x=%2f",
        "ftp://example.com/a/%2e%2e/b?x=%2f",
        "https://user:secret@example.com/a/%2e%2e/b?x=%2f",
        "https://example.com/a/%2e%2e/b?x=%2f#secret",
        "https://example.com:99999/a/%2e%2e/b?x=%2f",
    ] {
        rejected(&client, uri, raw, RawRequestErrorKind::InvalidDestination);
    }
    rejected(
        &client,
        "https://example.com/b?x=%2f",
        raw,
        RawRequestErrorKind::TargetMismatch,
    );
    rejected(
        &client,
        "https://example.com/a/%2e%2e/b?x=%2F",
        raw,
        RawRequestErrorKind::TargetMismatch,
    );
    import(
        &client,
        "https://example.com/a/%2e%2e/b?x=%2f",
        raw,
        raw.len(),
    )?;
    Ok(())
}

#[test]
fn only_origin_form_and_non_connect_methods_are_imported() -> TestResult {
    let client = client()?;
    for line in [
        "GET https://example.com/ HTTP/1.1",
        "OPTIONS * HTTP/1.1",
        "CONNECT example.com:443 HTTP/1.1",
        "CONNECT / HTTP/1.1",
    ] {
        let raw = format!("{line}\r\nHost: example.com\r\n\r\n");
        rejected(
            &client,
            "https://example.com/",
            raw.as_bytes(),
            RawRequestErrorKind::UnsupportedTarget,
        );
    }
    Ok(())
}

#[test]
fn host_is_single_canonical_authority_with_explicit_port_preserved() -> TestResult {
    let client = client()?;
    for (uri, host) in [
        ("https://EXAMPLE.com/", "example.COM"),
        ("https://example.com:443/", "example.com:443"),
        ("http://example.com:80/", "example.com:80"),
        ("https://[::1]:443/", "[0:0:0:0:0:0:0:1]:443"),
        ("https://bücher.example/", "xn--bcher-kva.example"),
    ] {
        let raw = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        import(&client, uri, raw.as_bytes(), raw.len())?;
    }
    for (uri, host) in [
        ("https://example.com/", "example.com:443"),
        ("https://example.com:443/", "example.com"),
        ("https://example.com/", "other.example"),
        ("https://example.com:443/", "example.com:444"),
    ] {
        let raw = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        rejected(
            &client,
            uri,
            raw.as_bytes(),
            RawRequestErrorKind::HostMismatch,
        );
    }
    for fields in [
        "",
        "Host: example.com\r\nHost: example.com\r\n",
        "Host:\r\n",
        "Host: example.com:99999\r\n",
        "Host: user@example.com\r\n",
        "Host: example.com/path\r\n",
    ] {
        let raw = format!("GET / HTTP/1.1\r\n{fields}\r\n");
        rejected(
            &client,
            "https://example.com/",
            raw.as_bytes(),
            RawRequestErrorKind::InvalidHost,
        );
    }
    Ok(())
}

#[test]
fn input_head_and_field_count_limits_have_exact_boundaries() -> TestResult {
    let client = client()?;
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(
        import(&client, "https://example.com/", raw, raw.len() - 1)
            .err()
            .ok_or("oversized input accepted")?
            .kind(),
        RawRequestErrorKind::InputTooLarge
    );
    import(&client, "https://example.com/", raw, raw.len())?;
    assert_eq!(
        import(&client, "invalid", &[0; 10], 0)
            .err()
            .ok_or("oversized input accepted")?
            .kind(),
        RawRequestErrorKind::InputTooLarge
    );

    let mut head = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Pad: ".to_vec();
    head.resize(MAXIMUM_HEAD_BYTES - 4, b'a');
    head.extend_from_slice(b"\r\n\r\n");
    import(&client, "https://example.com/", &head, head.len())?;
    head.insert(head.len() - 4, b'a');
    rejected(
        &client,
        "https://example.com/",
        &head,
        RawRequestErrorKind::HeadTooLarge,
    );

    let mut head = b"GET / HTTP/1.1\r\nHost: example.com\r\n".to_vec();
    for _ in 1..MAXIMUM_HEADERS {
        head.extend_from_slice(b"X: a\r\n");
    }
    head.extend_from_slice(b"\r\n");
    import(&client, "https://example.com/", &head, head.len())?;
    head.truncate(head.len() - 2);
    head.extend_from_slice(b"X: a\r\n\r\n");
    rejected(
        &client,
        "https://example.com/",
        &head,
        RawRequestErrorKind::TooManyHeaders,
    );
    Ok(())
}

#[test]
fn binary_body_and_zero_length_are_complete_owned_messages() -> TestResult {
    let client = client()?;
    for raw in [
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n\0\r\n\xff".as_slice(),
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ] {
        import(&client, "https://example.com/", raw, raw.len())?;
    }
    Ok(())
}

#[test]
fn failures_and_builder_debug_do_not_include_supplied_secrets() -> TestResult {
    let client = client()?;
    let secret = "raw-request-secret-canary";
    let raw = format!(
        "GET /?{secret} HTTP/1.1\r\nHost: example.com\r\nAuthorization: {secret}\r\nX-Secret: {secret}\r\n\r\n"
    );
    let request = import(
        &client,
        &format!("https://example.com/?{secret}"),
        raw.as_bytes(),
        raw.len(),
    )?;
    assert!(!format!("{request:?}").contains(secret));
    let error = import(
        &client,
        &format!("https://{secret}@example.com/"),
        raw.as_bytes(),
        raw.len(),
    )
    .err()
    .ok_or("invalid destination accepted")?;
    assert!(!format!("{error:?}: {error}").contains(secret));
    assert!(error.source().is_none());
    Ok(())
}

#[test]
fn unsupported_client_protocol_retains_the_original_request_error() -> TestResult {
    let mut tls = chrome::v154_tcp_tls();
    tls.alpn_protocols = vec![b"h2".as_slice().into()];
    let client =
        Client::builder(ClientProfile::new(tls).with_http2(chrome::v154_http2())).build()?;
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let error = import(&client, "https://example.com/", raw, raw.len())
        .err()
        .ok_or("unsupported protocol accepted")?;
    assert_eq!(error.kind(), RawRequestErrorKind::Request);
    let source = error
        .source()
        .and_then(|error| error.downcast_ref::<RequestError>())
        .ok_or("missing RequestError source")?;
    assert_eq!(source.kind(), crate::RequestErrorKind::ProtocolUnavailable);
    Ok(())
}
