//! Caller cookie placement through the public client, with or without a jar.

use super::*;
use phantom::profile::RequestField;

fn template() -> RequestTemplate {
    let multiplexed = vec![
        RequestField::literal("accept", "*/*"),
        RequestField::caller("x-middle"),
        RequestField::literal("priority", "u=4"),
    ];
    RequestTemplate {
        http1_fields: vec![
            RequestField::literal("Accept", "*/*"),
            RequestField::caller("X-Middle"),
        ],
        http2_fields: multiplexed.clone(),
        http3_fields: Some(multiplexed),
        http2_priority: None,
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    }
}

fn caller_fields() -> Vec<RequestHeader> {
    vec![
        RequestHeader::new("cOoKiE", "first=1").sensitive(),
        RequestHeader::new("x-middle", "caller"),
        RequestHeader::new("COOKIE", "last=2"),
    ]
}

fn assert_fields(observed: &Fields, protocol: HttpProtocol) {
    let names: Vec<_> = observed.iter().map(|(name, _)| name.as_str()).collect();
    if protocol == HttpProtocol::Http1 {
        assert_eq!(names, ["Accept", "X-Middle", "Cookie", "Cookie"]);
    } else {
        assert_eq!(
            names,
            ["accept", "x-middle", "cookie", "cookie", "priority"]
        );
    }
    let cookies: Vec<_> = observed
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(cookies, ["first=1", "last=2"]);
    assert_eq!(observed[1].1, "caller");
}

#[tokio::test]
async fn exact_protocols_place_caller_cookies_without_a_cookie_jar() -> TestResult<()> {
    let mut browser = chrome();
    browser.hints = None;
    for protocol in [
        HttpProtocol::Http1,
        HttpProtocol::Http2,
        HttpProtocol::Http3,
    ] {
        let observed = timeout(
            TEST_TIMEOUT,
            send_with(
                &browser,
                template(),
                protocol,
                caller_fields(),
                chrome::v154_cookie_placement(),
                |builder, _| Ok(builder),
            ),
        )
        .await??;
        assert_fields(&observed.fields, protocol);
    }
    Ok(())
}

#[tokio::test]
async fn negotiated_protocols_place_caller_cookies_after_alpn_selection() -> TestResult<()> {
    for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
        let identity = TestIdentity::generate()?;
        let (client_done, wait_for_client) = oneshot::channel();
        let (url, server) = if protocol == HttpProtocol::Http1 {
            serve_http1(&identity).await?
        } else {
            serve_http2(&identity, wait_for_client).await?
        };
        let server = ConnectionPeer::from_task(server);
        let operation: TestResult<Client> = async {
            let client = Client::builder(
                ClientProfile::new(tls_settings())
                    .with_http2(chrome().http2)
                    .with_cookie_placement(chrome::v154_cookie_placement()),
            )
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
            let sent = client
                .get(&url)?
                .template(&PreparedRequestTemplate::new(template())?)
                .headers(caller_fields())
                .send();
            let response = timeout(TEST_TIMEOUT, sent).await??;
            assert_eq!(
                response
                    .extensions()
                    .get::<ResponseInfo>()
                    .map(ResponseInfo::protocol),
                Some(protocol)
            );
            response.into_body().collect().await?;
            let _ = client_done.send(());
            Ok(client)
        }
        .await;
        let (_client, observed) = complete_peer(server, operation).await?;
        assert_fields(&observed.fields, protocol);
    }
    Ok(())
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn caller_cookie_placement_takes_precedence_over_the_jar() -> TestResult<()> {
    let mut browser = chrome();
    browser.hints = None;
    for protocol in [
        HttpProtocol::Http1,
        HttpProtocol::Http2,
        HttpProtocol::Http3,
    ] {
        let observed = timeout(
            TEST_TIMEOUT,
            send_with(
                &browser,
                template(),
                protocol,
                caller_fields(),
                chrome::v154_cookie_placement(),
                |builder, url| {
                    let jar = phantom::CookieJar::default();
                    jar.set_cookie(url, "jar=hidden; Path=/")?;
                    Ok(builder.cookie_jar(jar))
                },
            ),
        )
        .await??;
        assert_fields(&observed.fields, protocol);
    }
    Ok(())
}

#[tokio::test]
async fn caller_cookie_placement_also_applies_without_a_template() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (url, server) = serve_http1(&identity).await?;
    let server = ConnectionPeer::from_task(server);
    let operation: TestResult<()> = async {
        let client = Client::builder(
            ClientProfile::new(tls_settings())
                .with_cookie_placement(CookiePlacement::before_fields(["X-Middle"])),
        )
        .add_root_certificate_der(identity.root_der.clone())
        .build()?;
        let response = timeout(
            TEST_TIMEOUT,
            client
                .get_with_protocol(HttpProtocol::Http1, &url)?
                .headers(caller_fields())
                .send(),
        )
        .await??;
        response.into_body().collect().await?;
        Ok(())
    }
    .await;
    let ((), observed) = complete_peer(server, operation).await?;
    assert_eq!(
        observed.fields,
        [
            ("Cookie".to_owned(), "first=1".to_owned()),
            ("Cookie".to_owned(), "last=2".to_owned()),
            ("x-middle".to_owned(), "caller".to_owned()),
        ]
    );
    Ok(())
}
