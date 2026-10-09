//! Profile defaults and per-request choices as observed by loopback origins.

use std::{future::Future, net::Ipv4Addr, num::NonZeroUsize};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, PreparedRequestTemplate, RedirectPolicy, RequestBuilder,
    RequestErrorKind, RequestHeader,
    profile::{ClientProfile, Http2Priority, RequestField, RequestTemplate, browser::chrome},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, time::timeout};

use super::{
    Observed, TEST_TIMEOUT, TestIdentity, TestResult, client_settings, http1_fields, read_head,
    serve_http1, serve_http2, serve_http3, tls_settings,
};
use crate::support::tls::accept_tls_stream;

async fn bounded<T>(future: impl Future<Output = TestResult<T>>) -> TestResult<T> {
    timeout(TEST_TIMEOUT, future).await?
}

fn template(value: &str) -> RequestTemplate {
    RequestTemplate {
        http1_fields: vec![RequestField::literal("X-Default", value)],
        http2_fields: vec![RequestField::literal("x-default", value)],
        http3_fields: Some(vec![RequestField::literal("x-default", value)]),
        http2_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 37,
            exclusive: true,
        }),
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    }
}

async fn observe(
    protocol: HttpProtocol,
    negotiated: bool,
    configure: impl FnOnce(RequestBuilder) -> TestResult<RequestBuilder>,
) -> TestResult<Observed> {
    let identity = TestIdentity::generate()?;
    let (client_done, wait_for_client) = oneshot::channel();
    let (url, server) = match protocol {
        HttpProtocol::Http1 => serve_http1(&identity).await?,
        HttpProtocol::Http2 => serve_http2(&identity, wait_for_client).await?,
        HttpProtocol::Http3 => serve_http3(&identity, wait_for_client)?,
        _ => return Err("no origin for this protocol".into()),
    };
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chrome::v154_http2())
        .with_http3(client_settings())
        .with_request_template(template("inherited"));
    let client = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?;
    let request = if negotiated {
        client.get_negotiated(&url)?
    } else {
        client.get(protocol, &url)?
    };
    let response = configure(request)?.send().await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    let _ = client_done.send(());
    server.await?
}

#[tokio::test]
async fn profile_default_reaches_all_protocols_in_order() -> TestResult<()> {
    bounded(async {
        for protocol in [
            HttpProtocol::Http1,
            HttpProtocol::Http2,
            HttpProtocol::Http3,
        ] {
            let observed = observe(protocol, false, |request| {
                Ok(request.header(RequestHeader::new("x-caller", "custom")))
            })
            .await?;
            let name = if protocol == HttpProtocol::Http1 {
                "X-Default"
            } else {
                "x-default"
            };
            assert_eq!(
                observed.fields,
                vec![
                    (name.to_owned(), "inherited".to_owned()),
                    ("x-caller".to_owned(), "custom".to_owned()),
                ],
                "{protocol:?}"
            );
            if protocol == HttpProtocol::Http2 {
                assert_eq!(observed.priority, Some((true, 0, 37)));
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_request_inherits_default_fields_and_priority() -> TestResult<()> {
    bounded(async {
        let observed = observe(HttpProtocol::Http2, true, Ok).await?;
        assert_eq!(
            observed.fields,
            vec![("x-default".to_owned(), "inherited".to_owned())]
        );
        assert_eq!(observed.priority, Some((true, 0, 37)));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn caller_value_takes_the_inherited_position_without_identity_checks() -> TestResult<()> {
    bounded(async {
        let observed = observe(HttpProtocol::Http1, false, |request| {
            Ok(request
                .header(RequestHeader::new("x-default", "caller override"))
                .header(RequestHeader::new("User-Agent", "custom identity")))
        })
        .await?;
        assert_eq!(
            observed.fields,
            vec![
                ("X-Default".to_owned(), "caller override".to_owned()),
                ("User-Agent".to_owned(), "custom identity".to_owned()),
            ]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn explicit_template_replaces_the_complete_default() -> TestResult<()> {
    bounded(async {
        let mut replacement = template("unused");
        replacement.http1_fields = vec![RequestField::literal("X-Explicit", "replacement")];
        let replacement = PreparedRequestTemplate::new(replacement)?;
        let observed = observe(HttpProtocol::Http1, false, |request| {
            Ok(request.template(&replacement))
        })
        .await?;
        assert_eq!(
            observed.fields,
            vec![("X-Explicit".to_owned(), "replacement".to_owned())]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn opting_out_sends_only_caller_fields() -> TestResult<()> {
    bounded(async {
        let observed = observe(HttpProtocol::Http1, false, |request| {
            Ok(request
                .without_template()
                .header(RequestHeader::new("User-Agent", "custom identity")))
        })
        .await?;
        assert_eq!(
            observed.fields,
            vec![("User-Agent".to_owned(), "custom identity".to_owned())]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn inherited_required_slot_is_checked_before_connecting() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut default = template("inherited");
        default
            .http1_fields
            .push(RequestField::required_caller("X-Required"));
        default
            .http2_fields
            .push(RequestField::required_caller("x-required"));
        default
            .http3_fields
            .as_mut()
            .ok_or("missing H3 fields")?
            .push(RequestField::required_caller("x-required"));
        let client =
            Client::builder(ClientProfile::new(tls_settings()).with_request_template(default))
                .build()?;
        let Err(error) = client
            .get(
                HttpProtocol::Http1,
                &format!("https://{}/", listener.local_addr()?),
            )?
            .send()
            .await
        else {
            panic!("missing required caller field was sent");
        };
        assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
        assert!(
            timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    })
    .await
}

async fn redirect_hops(opt_out: bool) -> TestResult<Vec<super::Fields>> {
    let identity = TestIdentity::generate()?;
    let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let first_url = format!("https://{}/", first.local_addr()?);
    let second_url = format!("https://{}/", second.local_addr()?);
    let acceptor = identity.acceptor(super::H1_ALPN)?;
    let return_url = first_url.clone();
    let server = tokio::spawn(async move {
        let mut observations = Vec::new();
        for (listener, location) in [
            (&first, Some(second_url)),
            (&second, Some(return_url)),
            (&first, None),
        ] {
            let (stream, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(stream, acceptor.clone()).await?;
            observations.push(http1_fields(read_head(&mut stream).await?)?);
            let reply = if let Some(location) = location {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            } else {
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned()
            };
            stream.write_all(reply.as_bytes()).await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observations)
    });
    let mut default = template("kept");
    default.http1_fields.extend([
        RequestField::literal("Authorization", "Bearer origin"),
        RequestField::literal("Proxy-Authorization", "Basic dGVzdDpzZWNyZXQ="),
    ]);
    let client = Client::builder(ClientProfile::new(tls_settings()).with_request_template(default))
        .add_root_certificate_der(identity.root_der.clone())
        .redirect_policy(RedirectPolicy::limited(
            NonZeroUsize::new(2).ok_or("zero limit")?,
        ))
        .build()?;
    let request = client.get(HttpProtocol::Http1, &first_url)?;
    let request = if opt_out {
        request.without_template()
    } else {
        request
    };
    let response = request.send().await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    server.await?
}

#[tokio::test]
async fn redirect_does_not_restore_default_credentials_when_returning_to_origin() -> TestResult<()>
{
    bounded(async {
        let observations = redirect_hops(false).await?;
        assert_eq!(observations.len(), 3);
        assert_eq!(
            observations[0],
            vec![
                ("X-Default".to_owned(), "kept".to_owned()),
                ("Authorization".to_owned(), "Bearer origin".to_owned()),
                (
                    "Proxy-Authorization".to_owned(),
                    "Basic dGVzdDpzZWNyZXQ=".to_owned()
                ),
            ]
        );
        for fields in &observations[1..] {
            assert_eq!(fields, &vec![("X-Default".to_owned(), "kept".to_owned())]);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn opting_out_survives_redirects_back_to_the_original_origin() -> TestResult<()> {
    bounded(async {
        let observations = redirect_hops(true).await?;
        assert_eq!(observations.len(), 3);
        assert!(observations.iter().all(Vec::is_empty));
        Ok(())
    })
    .await
}
