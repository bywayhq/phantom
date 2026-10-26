//! Resource templates through public clients and held-open HTTP/2 streams.

use std::{collections::BTreeMap, net::IpAddr};

use bytes::Bytes;
use phantom::{
    RequestBuilder,
    profile::catalog::{self, RequestTemplateKind},
};
use tokio::sync::mpsc;

use super::*;

const H1: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/lifecycle/chrome/156.0.8078.48/windows-11-26200/resources-h1.txt"
));
const H2: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/lifecycle/chrome/156.0.8078.48/windows-11-26200/resources.txt"
));
const H3: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/lifecycle/chrome/156.0.8078.48/windows-11-26200/resources-h3.txt"
));
const CONTEXTS: [(RequestTemplateKind, &str); 4] = [
    (RequestTemplateKind::Script, "script"),
    (RequestTemplateKind::Stylesheet, "stylesheet"),
    (RequestTemplateKind::Image, "image"),
    (RequestTemplateKind::Font, "font"),
];

fn template(kind: RequestTemplateKind) -> TestResult<PreparedRequestTemplate> {
    Ok(PreparedRequestTemplate::new(
        catalog::profile("chrome-156-windows")?.request_template(kind)?,
    )?)
}

fn profile() -> TestResult<ClientProfile> {
    let selected = catalog::profile("chrome-156-windows")?.instantiate(&[])?;
    Ok(ClientProfile::new(tls_settings())
        .with_http2(selected.http2().ok_or("Chrome has no H2 settings")?.clone())
        .with_http3(client_settings())
        .with_client_hints(
            selected
                .client_hints()
                .ok_or("Chrome has no hints")?
                .clone(),
        ))
}

fn resource_fields(protocol: HttpProtocol, resource: &str) -> TestResult<Fields> {
    let source = match protocol {
        HttpProtocol::Http1 => H1,
        HttpProtocol::Http2 => H2,
        HttpProtocol::Http3 => H3,
        _ => return Err("no resource fixture for this protocol".into()),
    };
    let records: BTreeMap<_, _> = source
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let prefix = format!("resource_{resource}_field");
    let count: usize = records
        .get(format!("{prefix}_count").as_str())
        .ok_or("resource fields missing")?
        .parse()?;
    let mut fields = Vec::new();
    for index in 0..count {
        let record = records
            .get(format!("{prefix}_{index}").as_str())
            .ok_or("resource field missing")?;
        let (name, value) = record
            .strip_prefix("name_hex:")
            .ok_or("field name missing")?
            .split_once(",value_hex:")
            .ok_or("field value missing")?;
        let decode = |value: &str| -> TestResult<String> {
            if !value.is_ascii() || !value.len().is_multiple_of(2) {
                return Err("odd fixture hex length".into());
            }
            let bytes = (0..value.len())
                .step_by(2)
                .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(String::from_utf8(bytes)?)
        };
        let name = decode(name)?;
        if !name.starts_with(':') && !name.eq_ignore_ascii_case("host") {
            fields.push((name, decode(value)?));
        }
    }
    Ok(fields)
}

async fn observe(
    kind: RequestTemplateKind,
    protocol: HttpProtocol,
    configure: impl FnOnce(RequestBuilder) -> RequestBuilder,
) -> TestResult<(Observed, String, String)> {
    let identity = TestIdentity::generate()?;
    let (done, wait) = oneshot::channel();
    let (url, server) = match protocol {
        HttpProtocol::Http1 => serve_http1(&identity).await?,
        HttpProtocol::Http2 => serve_http2(&identity, wait).await?,
        HttpProtocol::Http3 => serve_http3(&identity, wait)?,
        _ => return Err("unsupported resource test protocol".into()),
    };
    let server = TemplateOrigin::new(server, None);
    let referer = format!("{url}caller-page?fresh=1");
    let origin = url.trim_end_matches('/').to_owned();
    let operation: TestResult<Client> = match timeout(TEST_TIMEOUT, async {
        let client = Client::builder(profile()?)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let mut request = client
            .get_with_protocol(protocol, &url)?
            .template(&template(kind)?)
            .header(RequestHeader::new("referer", referer.as_str()));
        if kind == RequestTemplateKind::Font {
            request = request.header(RequestHeader::new("origin", origin.as_str()));
        }
        let response = configure(request).send().await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        // The peer may already have exited if the request failed.
        let _ = done.send(());
        Ok::<_, Box<dyn Error + Send + Sync>>(client)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    match operation {
        Ok(client) => {
            let result = server.complete(Ok(())).await;
            drop(client);
            Ok((result?, referer, origin))
        }
        Err(error) => server
            .complete(Err(error))
            .await
            .map(|value| (value, referer, origin)),
    }
}

#[tokio::test]
async fn resource_contexts_send_the_captured_fields_on_all_three_protocols() -> TestResult<()> {
    for protocol in [
        HttpProtocol::Http1,
        HttpProtocol::Http2,
        HttpProtocol::Http3,
    ] {
        for (kind, resource) in CONTEXTS {
            let (observed, referer, origin) = observe(kind, protocol, |request| request).await?;
            let mut expected = resource_fields(protocol, resource)?;
            for (name, value) in &mut expected {
                if name.eq_ignore_ascii_case("referer") {
                    value.clone_from(&referer);
                }
                if name.eq_ignore_ascii_case("origin") {
                    value.clone_from(&origin);
                }
            }
            assert_eq!(observed.fields, expected, "{protocol:?} {kind:?}");
            if protocol == HttpProtocol::Http2 {
                let weight = if matches!(
                    kind,
                    RequestTemplateKind::Stylesheet | RequestTemplateKind::Font
                ) {
                    256
                } else {
                    147
                };
                assert_eq!(observed.priority, Some((true, 0, weight)));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn resource_caller_overrides_keep_the_captured_field_position() -> TestResult<()> {
    for protocol in [
        HttpProtocol::Http1,
        HttpProtocol::Http2,
        HttpProtocol::Http3,
    ] {
        let (observed, referer, origin) = observe(RequestTemplateKind::Font, protocol, |request| {
            request.header(RequestHeader::new("aCcEpT", "application/x-caller"))
        })
        .await?;
        let mut expected = resource_fields(protocol, "font")?;
        for (name, value) in &mut expected {
            match name.to_ascii_lowercase().as_str() {
                "accept" => *value = "application/x-caller".to_owned(),
                "referer" => value.clone_from(&referer),
                "origin" => value.clone_from(&origin),
                _ => {}
            }
        }
        assert_eq!(observed.fields, expected, "{protocol:?}");
    }
    Ok(())
}

#[tokio::test]
async fn missing_resource_slots_fail_before_tcp_or_quic_io() -> TestResult<()> {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let udp = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
    let client = Client::builder(profile()?).build()?;
    for protocol in [
        HttpProtocol::Http1,
        HttpProtocol::Http2,
        HttpProtocol::Http3,
    ] {
        let address = if protocol == HttpProtocol::Http3 {
            udp.local_addr()?
        } else {
            tcp.local_addr()?
        };
        let url = format!("https://{address}/resource");
        for (kind, _) in CONTEXTS {
            let mut request = client
                .get_with_protocol(protocol, &url)?
                .template(&template(kind)?);
            if kind == RequestTemplateKind::Font {
                request = request.header(RequestHeader::new("origin", "https://caller.example"));
            }
            let error = timeout(TEST_TIMEOUT, request.send())
                .await?
                .err()
                .ok_or("missing Referer was sent")?;
            assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
        }
        let request = client
            .get_with_protocol(protocol, &url)?
            .template(&template(RequestTemplateKind::Font)?)
            .header(RequestHeader::new("referer", "https://caller.example/page"));
        let error = timeout(TEST_TIMEOUT, request.send())
            .await?
            .err()
            .ok_or("missing font Origin was sent")?;
        assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
    }
    assert!(
        timeout(Duration::from_millis(100), tcp.accept())
            .await
            .is_err()
    );
    let error = udp
        .try_recv_from(&mut [0; 1])
        .err()
        .ok_or("resource validation sent a UDP datagram")?;
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    Ok(())
}

#[tokio::test]
async fn untrustworthy_http_resource_requests_omit_hints_and_fetch_metadata() -> TestResult<()> {
    for (kind, resource) in CONTEXTS {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!(
            "http://untrusted.phantom.invalid:{}/",
            listener.local_addr()?.port()
        );
        let referer = format!("{url}caller-page");
        let origin = url.trim_end_matches('/').to_owned();
        let peer = ConnectionPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let fields = http1_fields(read_head(&mut stream).await?)?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(fields)
        });
        let operation: TestResult<()> = match timeout(TEST_TIMEOUT, async {
            let client = Client::builder(profile()?)
                .resolve(
                    "untrusted.phantom.invalid",
                    [IpAddr::V4(Ipv4Addr::LOCALHOST)],
                )
                .build()?;
            let mut request = client
                .get_with_protocol(HttpProtocol::Http1, &url)?
                .template(&template(kind)?)
                .header(RequestHeader::new("referer", referer.as_str()));
            if kind == RequestTemplateKind::Font {
                request = request.header(RequestHeader::new("origin", origin.as_str()));
            }
            request.send().await?.into_body().collect().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        })
        .await
        {
            Ok(result) => result,
            Err(error) => Err(error.into()),
        };
        let ((), observed) = complete_peer(peer, operation).await?;
        let mut expected = resource_fields(HttpProtocol::Http1, resource)?;
        expected.retain(|(name, _)| !name.to_ascii_lowercase().starts_with("sec-"));
        for (name, value) in &mut expected {
            match name.to_ascii_lowercase().as_str() {
                "accept-encoding" => *value = "gzip, deflate".to_owned(),
                "referer" => value.clone_from(&referer),
                "origin" => value.clone_from(&origin),
                _ => {}
            }
        }
        assert_eq!(observed, expected, "{kind:?}");
    }
    Ok(())
}

async fn pooled_resources(negotiated: bool) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("https://{}/", listener.local_addr()?);
    let acceptor = identity.acceptor(H2_ALPN)?;
    let (release, mut releases) = mpsc::channel::<usize>(6);
    let (done, mut wait) = oneshot::channel();
    let peer = ConnectionPeer::spawn(async move {
        let wire = Arc::new(Mutex::new(Vec::new()));
        let stream = RecordingIo {
            inner: accept_tls(listener, acceptor).await?,
            read: Arc::clone(&wire),
        };
        let mut connection = ::http2::server::handshake(stream).await?;
        let mut bodies: Vec<Option<::http2::SendStream<Bytes>>> = Vec::new();
        let mut observed = Vec::new();
        loop {
            tokio::select! {
                accepted = connection.accept() => {
                    let (_request, mut respond) = accepted.ok_or("pooled H2 closed early")??;
                    let id = u32::from(respond.stream_id());
                    let priority = headers_priority(&wire.lock().map_err(|_| "wire lock poisoned")?, id)?;
                    observed.push((id, priority));
                    bodies.push(Some(respond.send_response(Response::builder().status(StatusCode::OK).body(())?, false)?));
                }
                index = releases.recv() => {
                    let mut body = bodies.get_mut(index.ok_or("release channel closed")?)
                        .and_then(Option::take).ok_or("resource response was not held")?;
                    body.send_data(Bytes::new(), true)?;
                }
                _ = &mut wait => {
                    assert_eq!(observed.len(), 6);
                    assert!(bodies.iter().all(Option::is_none));
                    break;
                }
            }
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(observed)
    });
    let operation: TestResult<Client> = match timeout(TEST_TIMEOUT, async {
        let client = Client::builder(profile()?)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let mut responses = Vec::new();
        for kind in [
            RequestTemplateKind::Stylesheet,
            RequestTemplateKind::Script,
            RequestTemplateKind::Image,
            RequestTemplateKind::Font,
        ] {
            let request = if negotiated {
                client.get(&url)?
            } else {
                client.get_with_protocol(HttpProtocol::Http2, &url)?
            };
            let mut request = request
                .template(&template(kind)?)
                .header(RequestHeader::new("referer", format!("{url}page")));
            if kind == RequestTemplateKind::Font {
                request = request.header(RequestHeader::new("origin", url.trim_end_matches('/')));
            }
            let response = timeout(TEST_TIMEOUT, request.send()).await??;
            assert_eq!(
                response
                    .extensions()
                    .get::<ResponseInfo>()
                    .map(ResponseInfo::protocol),
                Some(HttpProtocol::Http2)
            );
            responses.push(Some(response));
        }
        // Receiving END_STREAM retires the image even while its Response stays
        // application-owned. The older script remains the same-band parent.
        release.send(2).await?;
        responses[2]
            .as_mut()
            .ok_or("image response missing")?
            .body_mut()
            .collect()
            .await?;
        let request = if negotiated {
            client.get(&url)?
        } else {
            client.get_with_protocol(HttpProtocol::Http2, &url)?
        };
        responses.push(Some(
            request
                .template(&template(RequestTemplateKind::Script)?)
                .header(RequestHeader::new("referer", format!("{url}page")))
                .send()
                .await?,
        ));
        for index in [0, 1, 3, 4] {
            release.send(index).await?;
            responses[index]
                .take()
                .ok_or("response missing")?
                .into_body()
                .collect()
                .await?;
        }
        let request = if negotiated {
            client.get(&url)?
        } else {
            client.get_with_protocol(HttpProtocol::Http2, &url)?
        };
        let last = request
            .template(&template(RequestTemplateKind::Font)?)
            .header(RequestHeader::new("referer", format!("{url}page")))
            .header(RequestHeader::new("origin", url.trim_end_matches('/')))
            .send()
            .await?;
        release.send(5).await?;
        last.into_body().collect().await?;
        // The peer is still owned and joined below even if it already failed.
        let _ = done.send(());
        Ok::<_, Box<dyn Error + Send + Sync>>(client)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    let (_client, observed) = complete_peer(peer, operation).await?;
    let ids: Vec<_> = observed.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        observed
            .iter()
            .map(|(_, priority)| *priority)
            .collect::<Vec<_>>(),
        [
            Some((true, 0, 256)),
            Some((true, ids[0], 147)),
            Some((true, ids[1], 147)),
            Some((true, ids[0], 256)),
            Some((true, ids[1], 147)),
            Some((true, 0, 256)),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn exact_pooled_resources_select_live_parents_and_retire_completed_streams() -> TestResult<()>
{
    pooled_resources(false).await
}

#[tokio::test]
async fn negotiated_pooled_resources_select_live_parents_and_retire_completed_streams()
-> TestResult<()> {
    pooled_resources(true).await
}
