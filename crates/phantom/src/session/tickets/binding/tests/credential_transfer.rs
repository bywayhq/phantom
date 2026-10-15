//! Actual native authorization of opaque configured route credentials.

use std::{
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use btls::{
    pkey::PKey,
    ssl::{
        ScopedSslSession, SessionPolicyBinding, SessionTransferError, SessionTransferPolicy, Ssl,
        SslAcceptor, SslConnector, SslMethod, SslSessionScope, SslVersion,
    },
    x509::X509,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_btls::SslStream;

use super::{TestResult, route_bytes};
use crate::{ConnectUdpProxy, HttpProxy, Route, Socks4Proxy, Socks5Proxy};

const NAME: &str = "transfer.example";
const TIMEOUT: Duration = Duration::from_secs(10);

fn client(
    certificate: &X509,
    version: SslVersion,
) -> Result<SslConnector, Box<dyn std::error::Error>> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.cert_store_mut().add_cert(certificate.clone())?;
    builder.set_min_proto_version(Some(version))?;
    builder.set_max_proto_version(Some(version))?;
    builder.enable_scoped_client_sessions();
    Ok(builder.build())
}

fn bind(
    client: &SslConnector,
    scope: &SslSessionScope,
    route: &Route,
    policy: &[u8],
    key: &[u8; 32],
) -> Result<SessionPolicyBinding, Box<dyn std::error::Error>> {
    Ok(scope.bind_transfer_policy(
        client.context(),
        NAME,
        SessionTransferPolicy::new(
            policy,
            &[0, 0],
            crate::route::transfer_credential(route)?,
            key,
        )?,
    )?)
}

async fn source(
    route: &Route,
    policy: &[u8],
    version: SslVersion,
) -> Result<(ScopedSslSession, SessionPolicyBinding, X509), Box<dyn std::error::Error>> {
    let identity = rcgen::generate_simple_self_signed(vec![NAME.to_owned()])?;
    let certificate = X509::from_der(identity.cert.der())?;
    let key = PKey::private_key_from_pkcs8(&identity.signing_key.serialize_der())?;
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    builder.set_certificate(&certificate)?;
    builder.set_private_key(&key)?;
    builder.check_private_key()?;
    builder.set_min_proto_version(Some(version))?;
    builder.set_max_proto_version(Some(version))?;
    let acceptor = builder.build();
    let client = client(&certificate, version)?;
    let scope = SslSessionScope::default();
    let binding = bind(&client, &scope, route, policy, &[1; 32])?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let publication = Arc::clone(&captured);
    let mut configuration = client.configure()?;
    configuration.set_session_transfer_policy(&binding)?;
    let ssl = configuration
        .into_ssl_with_session_transfer(NAME, &scope, None, move |session| {
            publication
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(session);
        })?
        .ok_or("TLS finalization declined")?;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let mut client_stream = SslStream::new(ssl, client_io)?;
    let mut server_stream = SslStream::new(Ssl::new(acceptor.context())?, server_io)?;
    // Both futures are owned here. Error, timeout or panic drops both; no spawned peer survives.
    tokio::time::timeout(TIMEOUT, async {
        tokio::try_join!(
            async {
                Pin::new(&mut client_stream).connect().await?;
                let mut reply = [0];
                client_stream.read_exact(&mut reply).await?;
                assert_eq!(reply, [b'x']);
                assert!(
                    client_stream
                        .ssl()
                        .authenticate_scoped_session_publication()
                );
                Ok::<_, Box<dyn std::error::Error>>(())
            },
            async {
                Pin::new(&mut server_stream).accept().await?;
                server_stream.write_all(b"x").await?;
                server_stream.flush().await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            }
        )
    })
    .await??;
    let session = captured
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .pop()
        .ok_or("authenticated TLS ticket absent")??;
    assert!(session.is_authenticated());
    Ok((session, binding, certificate))
}

#[tokio::test]
async fn native_credentials_authorize_equal_values_across_keys_and_reject_changed_values()
-> TestResult {
    let pairs = [
        (
            Route::http_proxy(
                HttpProxy::new("https://proxy.example")?.with_basic_auth("user", "password")?,
            ),
            Route::http_proxy(
                HttpProxy::new("https://proxy.example")?.with_basic_auth("user", "changed")?,
            ),
        ),
        (
            Route::http_proxy(
                HttpProxy::new("https://proxy.example")?.with_digest_auth("user", "password")?,
            ),
            Route::http_proxy(
                HttpProxy::new("https://proxy.example")?.with_digest_auth("user", "changed")?,
            ),
        ),
        (
            Route::http_proxy(
                HttpProxy::new("https://proxy.example")?.with_digest_auth("ab", "c")?,
            ),
            Route::http_proxy(
                HttpProxy::new("https://proxy.example")?.with_digest_auth("a", "bc")?,
            ),
        ),
        (
            Route::socks4(Socks4Proxy::new("socks4a://proxy.example")?),
            Route::socks4(Socks4Proxy::new("socks4a://proxy.example")?.with_user_id("changed")?),
        ),
        (
            Route::socks4(Socks4Proxy::new("socks4a://proxy.example")?.with_user_id("user")?),
            Route::socks4(Socks4Proxy::new("socks4a://proxy.example")?.with_user_id("changed")?),
        ),
        (
            Route::socks5(
                Socks5Proxy::new("socks5h://proxy.example")?
                    .with_username_password("user", "password")?,
            ),
            Route::socks5(
                Socks5Proxy::new("socks5h://proxy.example")?
                    .with_username_password("user", "changed")?,
            ),
        ),
        (
            Route::connect_udp(
                ConnectUdpProxy::new("https://proxy.example/udp/{target_host}/{target_port}/")?
                    .with_basic_auth("user", "password")?,
            ),
            Route::connect_udp(
                ConnectUdpProxy::new("https://proxy.example/udp/{target_host}/{target_port}/")?
                    .with_basic_auth("user", "changed")?,
            ),
        ),
        (
            Route::socks5(
                Socks5Proxy::new("socks5h://proxy.example")?.with_username_password("ab", "c")?,
            ),
            Route::socks5(
                Socks5Proxy::new("socks5h://proxy.example")?.with_username_password("a", "bc")?,
            ),
        ),
    ];
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for (configured, changed) in &pairs {
            let policy = route_bytes(configured)?;
            assert_eq!(policy, route_bytes(changed)?);
            let (session, source, certificate) = source(configured, &policy, version).await?;
            let record = source.seal_session(&session, b"synthetic owner metadata", &[7; 32])?;
            let envelope = btls::ssl::seal_envelope(&[record], &[7; 32])?;
            let recipient = client(&certificate, version)?;
            let wrong_scope = SslSessionScope::default();
            let wrong = bind(&recipient, &wrong_scope, changed, &policy, &[2; 32])?;
            let mut opened =
                btls::ssl::open_envelope(envelope.as_bytes(), &[7; 32], recipient.context())?;
            assert!(matches!(
                opened.authorize_record(0, &wrong),
                Err(SessionTransferError::Credentials)
            ));
            assert_eq!(opened.owner_metadata(0)?, b"synthetic owner metadata");
            let scope = SslSessionScope::default();
            let right = bind(&recipient, &scope, configured, &policy, &[2; 32])?;
            let permit = opened.authorize_record(0, &right)?;
            let imported = permit.into_scoped_session()?;
            assert!(imported.is_authenticated());
            assert!(session.is_authenticated());
        }
    }
    Ok(())
}

#[tokio::test]
async fn absent_input_differs_from_empty_socks4_user_id_at_native_authorization() -> TestResult {
    let empty = Route::socks4(Socks4Proxy::new("socks4a://proxy.example")?);
    assert!(crate::route::transfer_credential(&empty)?.is_some());
    for absent in [
        Route::Direct,
        Route::http_proxy(HttpProxy::new("https://proxy.example")?),
        Route::socks5(Socks5Proxy::new("socks5h://proxy.example")?),
        Route::connect_udp(ConnectUdpProxy::new(
            "https://proxy.example/udp/{target_host}/{target_port}/",
        )?),
    ] {
        assert!(crate::route::transfer_credential(&absent)?.is_none());
    }
    // Hold noncredential policy equal to isolate native None-versus-Some input handling.
    let policy = b"synthetic identical noncredential policy";
    let (session, source, certificate) = source(&empty, policy, SslVersion::TLS1_3).await?;
    let record = source.seal_session(&session, b"metadata", &[7; 32])?;
    let envelope = btls::ssl::seal_envelope(&[record], &[7; 32])?;
    let recipient = client(&certificate, SslVersion::TLS1_3)?;
    let scope = SslSessionScope::default();
    let absent = bind(&recipient, &scope, &Route::Direct, policy, &[2; 32])?;
    let mut opened = btls::ssl::open_envelope(envelope.as_bytes(), &[7; 32], recipient.context())?;
    assert!(matches!(
        opened.authorize_record(0, &absent),
        Err(SessionTransferError::Credentials)
    ));
    Ok(())
}

#[tokio::test]
async fn http_and_connect_udp_basic_owners_produce_the_same_native_credential_input() -> TestResult
{
    let http = Route::http_proxy(
        HttpProxy::new("https://proxy.example")?.with_basic_auth("user", "password")?,
    );
    let udp = Route::connect_udp(
        ConnectUdpProxy::new("https://proxy.example/udp/{target_host}/{target_port}/")?
            .with_basic_auth("user", "password")?,
    );
    assert_ne!(route_bytes(&http)?, route_bytes(&udp)?);
    // Only this native input control fixes policy equal; real route families remain isolated above.
    let policy = b"synthetic identical noncredential policy";
    let (session, source, certificate) = source(&http, policy, SslVersion::TLS1_3).await?;
    let record = source.seal_session(&session, b"metadata", &[7; 32])?;
    let envelope = btls::ssl::seal_envelope(&[record], &[7; 32])?;
    let recipient = client(&certificate, SslVersion::TLS1_3)?;
    let scope = SslSessionScope::default();
    let binding = bind(&recipient, &scope, &udp, policy, &[2; 32])?;
    let mut opened = btls::ssl::open_envelope(envelope.as_bytes(), &[7; 32], recipient.context())?;
    assert!(
        opened
            .authorize_record(0, &binding)?
            .into_scoped_session()?
            .is_authenticated()
    );
    Ok(())
}
