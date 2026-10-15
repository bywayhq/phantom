//! Genuine connector tickets over locally owned duplex streams.

use std::{pin::Pin, time::Duration};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslConnector, SslMethod, SslVersion, select_next_proto},
    x509::X509,
};
use http::Method;
use http_body_util::BodyExt;
use phantom_net::{
    request::{OriginForm, RequestHeader},
    route::{ConnectedStream, DirectTlsSetup, Http1Route, Http1Target, OriginRoute, TcpRoute},
};
use phantom_profile::{EchSettings, TlsVersion, TlsVersionRange};
use phantom_testkit::http1::{CaptureLimits, capture_request_head};
use tokio::io::AsyncWriteExt;
use tokio_btls::SslStream;

use super::*;

const TIMEOUT: Duration = Duration::from_secs(10);
const NAME: &str = "origin.example";
const OTHER: &str = "second.example";

struct Fixture {
    owner: TicketOwner,
    connector: Http1TlsConnector,
    endpoint: Endpoint,
    server: SslAcceptor,
}

impl Fixture {
    fn new(version: TlsVersion) -> TestResult<Self> {
        let identity = rcgen::generate_simple_self_signed(vec![NAME.into(), OTHER.into()])?;
        let root: Box<[u8]> = identity.cert.der().to_vec().into_boxed_slice();
        let certificate = X509::from_der(&root)?;
        let key = PKey::private_key_from_pkcs8(&identity.signing_key.serialize_der())?;
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        server.set_certificate(&certificate)?;
        server.set_private_key(&key)?;
        server.check_private_key()?;
        let native_version = match version {
            TlsVersion::Tls12 => SslVersion::TLS1_2,
            _ => SslVersion::TLS1_3,
        };
        server.set_min_proto_version(Some(native_version))?;
        server.set_max_proto_version(Some(native_version))?;
        server.set_alpn_select_callback(|_, offered| {
            select_next_proto(b"\x08http/1.1", offered).ok_or(AlpnError::NOACK)
        });
        let mut settings = chrome::v154_tcp_tls();
        settings.versions = TlsVersionRange::only(version);
        if version == TlsVersion::Tls12 {
            settings.alps = None;
            settings.key_shares.clear();
            settings.certificate_compression.clear();
            settings.ech = EchSettings::Disabled;
            settings.requested_trust_anchor_ids = None;
        }
        let profile = ClientProfile::new(settings);
        let owner = prepared(&profile, std::slice::from_ref(&root))?;
        let connector = Http1TlsConnector::new_with_additional_roots(profile.tls(), [&*root])?
            .with_isolated_session_cache();
        let endpoint = origin("origin.example:443")?;
        register(&owner, &connector, &endpoint);
        Ok(Self {
            owner,
            connector,
            endpoint,
            server: server.build(),
        })
    }
}

async fn seed(
    connector: &Http1TlsConnector,
    server: &SslAcceptor,
    endpoint: &Endpoint,
) -> TestResult {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let mut peer = SslStream::new(Ssl::new(server.context())?, server_io)?;
    // Both futures stay owned here. Error, timeout or panic drops both streams.
    tokio::time::timeout(TIMEOUT, async {
        tokio::try_join!(
            async {
                let response = connector
                    .send(
                        Http1Route::Origin(OriginRoute::Tls {
                            tcp: TcpRoute::Connected(ConnectedStream::new(client_io)),
                            server_name: endpoint.host(),
                            setup: DirectTlsSetup::Default,
                        }),
                        Method::GET,
                        Http1Target::Origin(OriginForm::parse("/")?),
                        vec![RequestHeader::new("Host", endpoint.authority().as_str())],
                        None,
                    )
                    .await?;
                assert_eq!(response.status(), http::StatusCode::OK);
                assert_eq!(
                    response.into_body().collect().await?.to_bytes().as_ref(),
                    b"x"
                );
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            },
            async {
                Pin::new(&mut peer).accept().await?;
                assert!(!peer.ssl().session_reused());
                let head = capture_request_head(
                    &mut peer,
                    tokio::time::Instant::now() + TIMEOUT,
                    CaptureLimits::new(32 * 1024, 8 * 1024, 32),
                )
                .await?;
                assert_eq!(head.method(), b"GET");
                peer.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
                )
                .await?;
                peer.flush().await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            }
        )?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn live_tls12_and_tls13_export_preserve_store_and_bind_actual_native_metadata() -> TestResult
{
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let fixture = Fixture::new(version)?;
        seed(&fixture.connector, &fixture.server, &fixture.endpoint).await?;
        let second = fixture.connector.with_isolated_session_cache();
        let other = origin("second.example:443")?;
        register(&fixture.owner, &second, &other);
        seed(&second, &fixture.server, &other).await?;
        let sealed = fixture.owner.export_tcp(&KEY)?;
        let opened = envelope::open_manifest(sealed.as_bytes(), &KEY)?;
        assert_eq!(opened.owner_count(), 2);
        assert!(opened.record_count() >= 2);
        let decoder = SslConnector::builder(SslMethod::tls())?.build();
        let verified =
            btls::ssl::open_envelope(opened.native_ciphertext(), &KEY, decoder.context())?;
        assert_eq!(verified.record_count(), opened.record_count());
        assert!(matches!(
            btls::ssl::open_envelope(opened.native_ciphertext(), &[12; 32], decoder.context()),
            Err(SessionTransferError::Authentication)
        ));
        let mut dense = 0;
        for owner in opened.owners() {
            let owner = owner?;
            assert!(owner.header.record_count() > 0);
            assert_eq!(owner.header.excluded_expired_count(), 0);
            for slot in owner.slots() {
                assert_eq!(usize::from(slot.native_slot), dense);
                assert_eq!(verified.source_witness(dense)?, owner.source_witness);
                let metadata =
                    phantom_net::TcpSessionRecordMetadata::parse(verified.owner_metadata(dense)?)?;
                assert_eq!(metadata.header(), owner.header);
                assert_eq!(metadata.hostname(), owner.server_name);
                assert_eq!(metadata.ordinal(), usize::from(slot.physical_ordinal));
                assert_eq!(metadata.payload(), owner_payload(owner.record_owner_index));
                dense += 1;
            }
        }
        assert_eq!(dense, opened.record_count());
        // A second export retains the same store counts, physical ordinals and counters.
        let repeat = fixture.owner.export_tcp(&KEY)?;
        let repeat = envelope::open_manifest(repeat.as_bytes(), &KEY)?;
        assert_eq!(repeat.record_count(), opened.record_count());
        for (before, after) in opened.owners().zip(repeat.owners()) {
            let (before, after) = (before?, after?);
            assert_eq!(before.header, after.header);
            assert_eq!(
                before.slots().collect::<Vec<_>>(),
                after.slots().collect::<Vec<_>>()
            );
        }
        assert_eq!(fixture.owner.clear(), opened.record_count());
    }
    Ok(())
}

#[tokio::test]
async fn conflicting_live_registration_rejects_export_without_consuming_real_tickets() -> TestResult
{
    let fixture = Fixture::new(TlsVersion::Tls13)?;
    seed(&fixture.connector, &fixture.server, &fixture.endpoint).await?;
    let sealed = fixture.owner.export_tcp(&KEY)?;
    let count = envelope::open_manifest(sealed.as_bytes(), &KEY)?.record_count();
    assert!(count > 0);
    let changed = origin("origin.example")?;
    register(&fixture.owner, &fixture.connector, &changed);
    assert!(matches!(
        fixture.owner.export_tcp(&KEY),
        Err(TcpExportError::ConflictingOwner)
    ));
    assert_eq!(fixture.owner.clear(), count);
    Ok(())
}
