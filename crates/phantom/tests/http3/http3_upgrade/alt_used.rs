//! Ordered fields emitted for Firefox alternative requests.

use super::*;
use phantom::PreparedRequestTemplate;

#[cfg(feature = "cookies")]
fn firefox_fields<'a>(
    navigation: bool,
    referer: Option<&'a str>,
    authority: &'a str,
) -> Vec<(&'static str, &'a [u8])> {
    let accept: &[u8] = if navigation {
        b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    } else {
        b"*/*"
    };
    let mut expected = vec![
        (
            "user-agent",
            b"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0"
                .as_slice(),
        ),
        ("accept", accept),
        ("accept-language", b"en-US,en;q=0.9".as_slice()),
        ("accept-encoding", b"gzip, deflate, br, zstd".as_slice()),
    ];
    if navigation {
        expected.push(("alt-used", authority.as_bytes()));
    }
    if let Some(referer) = referer {
        expected.push(("referer", referer.as_bytes()));
    }
    if !navigation {
        expected.push(("alt-used", authority.as_bytes()));
    }
    expected.push(("cookie", b"fixture=1"));
    if navigation {
        expected.push(("upgrade-insecure-requests", b"1"));
    }
    expected.extend([
        (
            "sec-fetch-dest",
            if navigation {
                b"document".as_slice()
            } else {
                b"empty"
            },
        ),
        (
            "sec-fetch-mode",
            if navigation {
                b"navigate".as_slice()
            } else {
                b"cors"
            },
        ),
        (
            "sec-fetch-site",
            if navigation {
                b"none".as_slice()
            } else {
                b"same-origin"
            },
        ),
    ]);
    if navigation {
        expected.push(("sec-fetch-user", b"?1"));
    }
    expected.push(("priority", if navigation { b"u=0, i" } else { b"u=4" }));
    expected
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn firefox_alternative_fields_place_alt_used_with_referer_and_cookie() -> TestResult<()> {
    for navigation in [true, false] {
        for referer in [None, Some("https://example.test/page")] {
            for pinned in [false, true] {
                bounded(async {
                    let identity = TestIdentity::generate()?;
                    let fixture = Http3UpgradeFixture::spawn(
                        &identity,
                        ORIGIN_NAME,
                        UpgradeScript::new(
                            [PlannedResponse::new(StatusCode::OK)
                                .header(
                                    "set-cookie",
                                    HeaderValue::from_static("fixture=1; Path=/; Secure"),
                                )
                                .advertise_alternative()],
                            AlternativeBehavior::responses([PlannedResponse::new(StatusCode::OK)]),
                        ),
                    )
                    .await?;
                    let authority = fixture.alternative_address().to_string();
                    let profile = ClientProfile::new(tls_settings())
                        .with_http2(chrome::v154_http2())
                        .with_http3(appending_alt_used(client_settings()))
                        .with_cookie_placement(firefox::v157_cookie_placement())
                        .with_client_hints(ClientHintSettings::new(vec![ClientHint::new(
                            "alt-used",
                            "spoofed.test:443",
                            ClientHintDelivery::Default,
                        )]));
                    let client = Client::builder(profile)
                        .add_root_certificate_der(identity.root_der.clone())
                        .cookies()
                        .alt_svc(NonZeroUsize::new(8).ok_or("zero capacity")?)
                        .build()?;
                    drain(client.get(&fixture.origin_url("/learn"))?.send().await?).await?;
                    let template = PreparedRequestTemplate::new(if navigation {
                        firefox::v157_windows_navigation_template()
                    } else {
                        firefox::v157_windows_fetch_template()
                    })?;
                    let mut request = if pinned {
                        client
                            .get_with_protocol(HttpProtocol::Http3, &fixture.origin_url("/fields"))?
                            .alt_svc_alternative(ORIGIN_NAME, fixture.alternative_address().port())
                    } else {
                        client.get(&fixture.origin_url("/fields"))?
                    }
                    .template(&template);
                    if let Some(referer) = referer {
                        request = request.header(RequestHeader::new("referer", referer));
                    }
                    let response = request.send().await?;
                    assert_eq!(protocol(&response)?, HttpProtocol::Http3);
                    drain(response).await?;
                    drop(client);
                    let observed = fixture.finish().await?;
                    assert_eq!(observed.alternative_requests.len(), 1);
                    let expected = firefox_fields(navigation, referer, &authority);
                    assert_eq!(
                        field_pairs(&observed.alternative_requests[0]),
                        expected,
                        "navigation={navigation}, referer={referer:?}, pinned={pinned}"
                    );
                    Ok(())
                })
                .await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn automatic_hints_cannot_inject_or_move_alt_used() -> TestResult<()> {
    use phantom::profile::{RequestField, RequestTemplate};
    for (delivery, learned) in [
        (ClientHintDelivery::Default, false),
        (ClientHintDelivery::AcceptCh, false),
        (ClientHintDelivery::AcceptCh, true),
    ] {
        for (alternative, emits) in [(true, true), (true, false), (false, true)] {
            bounded(async {
                let identity = TestIdentity::generate()?;
                let mut learn = PlannedResponse::new(StatusCode::OK).advertise_alternative();
                if learned {
                    learn = learn.header("accept-ch", HeaderValue::from_static("alt-used"));
                }
                let fixture = Http3UpgradeFixture::spawn(
                    &identity,
                    ORIGIN_NAME,
                    UpgradeScript::new(
                        [learn],
                        AlternativeBehavior::responses([PlannedResponse::new(StatusCode::OK)
                            .header("accept-ch", HeaderValue::from_static("alt-used"))
                            .header("critical-ch", HeaderValue::from_static("alt-used"))]),
                    ),
                )
                .await?;
                let fields = vec![
                    RequestField::ClientHints,
                    RequestField::literal("x-before", "one"),
                    RequestField::literal("x-after", "two"),
                ];
                let mut h3 = fields.clone();
                h3.insert(1, RequestField::AltUsed);
                let template = PreparedRequestTemplate::new(RequestTemplate {
                    http1_fields: fields.clone(),
                    http2_fields: fields,
                    http3_fields: Some(h3),
                    http2_priority: None,
                    requested_client_hint_placement: false,
                    restarts_for_connection_accept_ch: false,
                })?;
                let http3 = if emits {
                    appending_alt_used(client_settings())
                } else {
                    client_settings()
                };
                let profile = ClientProfile::new(tls_settings())
                    .with_http2(chrome::v154_http2())
                    .with_http3(http3)
                    .with_client_hints(ClientHintSettings::new(vec![
                        ClientHint::new("alt-used", "spoofed.test:443", delivery),
                        ClientHint::new("x-ordinary-hint", "ordinary", ClientHintDelivery::Default),
                    ]));
                let client = Client::builder(profile)
                    .add_root_certificate_der(identity.root_der.clone())
                    .alt_svc(NonZeroUsize::new(8).ok_or("zero capacity")?)
                    .build()?;
                drain(
                    client
                        .get(&fixture.origin_url("/learn"))?
                        .template(&template)
                        .send()
                        .await?,
                )
                .await?;
                let exact_url = format!("https://{}/fields", fixture.alternative_address());
                let request = if alternative {
                    client.get(&fixture.origin_url("/fields"))?
                } else {
                    client.get_with_protocol(HttpProtocol::Http3, &exact_url)?
                };
                let response = request.template(&template).send().await?;
                assert_eq!(protocol(&response)?, HttpProtocol::Http3);
                drain(response).await?;
                drop(client);
                let authority = fixture.alternative_address().to_string();
                let observed = fixture.finish().await?;
                assert_eq!(
                    observed.alternative_requests.len(),
                    1,
                    "reserved Critical-CH must not retry"
                );
                let mut expected = vec![("x-ordinary-hint", b"ordinary".as_slice())];
                if alternative && emits {
                    expected.push(("alt-used", authority.as_bytes()));
                }
                expected.extend([
                    ("x-before", b"one".as_slice()),
                    ("x-after", b"two".as_slice()),
                ]);
                assert_eq!(field_pairs(&observed.alternative_requests[0]), expected);
                assert_eq!(
                    field_pairs(&observed.origin_requests[0]),
                    [
                        ("x-ordinary-hint", b"ordinary".as_slice()),
                        ("x-before", b"one".as_slice()),
                        ("x-after", b"two".as_slice())
                    ]
                );
                Ok(())
            })
            .await?;
        }
    }
    Ok(())
}
