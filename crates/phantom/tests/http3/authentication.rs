//! HTTP/3 server authentication through the public client.

use std::{error::Error, time::Duration};

use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, ServerAuthentication, profile::ClientProfile,
};
use tokio::{sync::oneshot, time::timeout};

use crate::support::{
    h3::{accept_request, client_settings, server_endpoint},
    tls::{TestIdentity, TestResult, tls_settings},
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const DEADLINE: Duration = Duration::from_secs(5);

#[test]
fn http3_authentication_rejects_a_malformed_additional_root() -> TestResult<()> {
    let settings = client_settings();
    let error = phantom_net::http3::Http3Connector::new_with_additional_roots(
        settings.tls(),
        settings.quic_transport(),
        settings.http3(),
        settings.request(),
        [b"not-a-der-certificate".as_slice()],
    )
    .err()
    .ok_or("HTTP/3 accepted a malformed additional root")?;
    assert_eq!(
        error.kind(),
        phantom_net::http3::Http3ConnectorErrorKind::TrustStore
    );
    Ok(())
}

#[tokio::test]
async fn default_http3_authentication_rejects_an_untrusted_certificate() -> TestResult<()> {
    authenticate(
        TestIdentity::generate()?,
        false,
        ServerAuthentication::WebPki,
        false,
    )
    .await
}

#[tokio::test]
async fn default_http3_authentication_rejects_a_trusted_wrong_hostname() -> TestResult<()> {
    authenticate(
        TestIdentity::generate_for_dns("wrong.example")?,
        true,
        ServerAuthentication::WebPki,
        false,
    )
    .await
}

#[tokio::test]
async fn default_http3_authentication_accepts_a_trusted_matching_certificate() -> TestResult<()> {
    authenticate(
        TestIdentity::generate()?,
        true,
        ServerAuthentication::WebPki,
        true,
    )
    .await
}

#[cfg(feature = "danger-disable-verification")]
#[tokio::test]
async fn explicit_disabled_http3_authentication_accepts_untrusted_wrong_hostname() -> TestResult<()>
{
    authenticate(
        TestIdentity::generate_for_dns("wrong.example")?,
        false,
        ServerAuthentication::DangerDisabled,
        true,
    )
    .await
}

#[cfg(feature = "danger-disable-verification")]
#[tokio::test]
async fn explicit_disabled_http3_authentication_supports_ticket_enabled_browser_recipes()
-> TestResult<()> {
    for profile in [
        phantom::profile::browser::chrome::v154_windows(),
        phantom::profile::browser::firefox::v157_windows(),
    ] {
        let http3 = profile
            .http3()
            .ok_or("browser recipe has no HTTP/3 profile")?;
        assert!(http3.tls().session_tickets.is_enabled());
        authenticate_profile(
            TestIdentity::generate_for_dns("wrong.example")?,
            false,
            ServerAuthentication::DangerDisabled,
            true,
            profile,
        )
        .await?;
    }
    Ok(())
}

async fn authenticate(
    identity: TestIdentity,
    trust_root: bool,
    policy: ServerAuthentication,
    succeeds: bool,
) -> TestResult<()> {
    authenticate_profile(
        identity,
        trust_root,
        policy,
        succeeds,
        ClientProfile::new(tls_settings()).with_http3(client_settings()),
    )
    .await
}

async fn authenticate_profile(
    identity: TestIdentity,
    trust_root: bool,
    policy: ServerAuthentication,
    succeeds: bool,
    profile: ClientProfile,
) -> TestResult<()> {
    let (address, endpoint) = server_endpoint(&identity)?;
    let (release, released) = oneshot::channel();
    let mut peer = ConnectionPeer::spawn(async move {
        if succeeds {
            let (request, mut stream, connection) = accept_request(&endpoint).await?;
            assert_eq!(request.uri().path(), "/authentication");
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(())?,
                )
                .await?;
            stream.finish().await?;
            released.await?;
            drop(connection);
        } else {
            let incoming = endpoint
                .accept()
                .await
                .ok_or("HTTP/3 authentication endpoint closed")?;
            if incoming.await.is_ok() {
                return Err(
                    "HTTP/3 peer accepted a handshake that must fail authentication".into(),
                );
            }
        }
        Ok(())
    });
    let result = timeout(DEADLINE, async {
        let mut builder = Client::builder(profile).server_authentication(policy);
        if trust_root {
            builder = builder.add_root_certificate_der(identity.root_der);
        }
        let client = builder.build()?;
        let response = client
            .get_with_protocol(
                HttpProtocol::Http3,
                &format!("https://{address}/authentication"),
            )?
            .send()
            .await;
        if succeeds {
            let response = response?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(response.into_body().collect().await?.to_bytes().is_empty());
            release
                .send(())
                .map_err(|_| "HTTP/3 peer dropped before the response was read")?;
        } else {
            let error = response
                .err()
                .ok_or("HTTP/3 accepted a certificate that must fail authentication")?;
            assert_eq!(error.kind(), RequestErrorKind::Tls);
            assert!(
                has_crypto_failure(&error),
                "authentication failed without a TLS failure: {error:?}"
            );
        }
        peer.join().await??;
        Ok(())
    })
    .await
    .map_err(|_| "HTTP/3 authentication control exceeded its deadline".into())
    .and_then(|result| result);
    finish_with_cleanup(result, peer.shutdown().await)
}

fn has_crypto_failure(error: &(dyn Error + 'static)) -> bool {
    if let Some(error) = error.downcast_ref::<quinn::ConnectionError>() {
        let code = match error {
            quinn::ConnectionError::TransportError(error) => error.code,
            quinn::ConnectionError::ConnectionClosed(error) => error.error_code,
            _ => return false,
        };
        return (0x100..0x200).contains(&u64::from(code));
    }
    error.source().is_some_and(has_crypto_failure)
}
