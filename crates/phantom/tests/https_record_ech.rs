//! Encrypted Client Hello from an HTTPS DNS record, through the client facade.

#![cfg(feature = "https-records")]

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use btls::{
    hpke::HpkeKey,
    ssl::{NameType, Ssl, SslAcceptor, SslEchKeys},
};
use http_body_util::BodyExt;
use phantom::{
    Client,
    dns::HttpsRecordResolver,
    profile::{CipherSuite, ClientProfile, NamedGroup, TlsSettings, TlsVersion, chromium},
};
use phantom_testkit::{
    dns::{DnsAnswer, DnsReply, DnsServer},
    tls::{CaptureLimits, TEST_ECH_KEYS, capture_client_hello, ech_config, ech_config_list},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_btls::SslStream;

use h3_support::client_settings;
use tls_support::{H1_ALPN, TestIdentity, TestResult, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const ORIGIN_NAME: &str = "localhost";
const STAND_IN_NAME: &str = "origin.test";
const PUBLIC_NAME: &str = "public.phantom.test";

/// What the origin saw on one connection.
#[derive(Debug)]
struct Observed {
    outer_server_name: Option<String>,
    ech_accepted: bool,
    inner_server_name: Option<String>,
}

/// A ServiceMode record at the owner name with `alpn=h2` and `ech`.
fn https_rdata(ech_config_list: &[u8]) -> Vec<u8> {
    let mut rdata = vec![0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 0x02, b'h', b'2'];
    rdata.extend_from_slice(&5_u16.to_be_bytes());
    rdata.extend_from_slice(&(ech_config_list.len() as u16).to_be_bytes());
    rdata.extend_from_slice(ech_config_list);
    rdata
}

/// TLS 1.3 test settings that offer ECH from HTTPS records, as Chrome 154's
/// recipe does.
fn ech_tls_settings() -> TlsSettings {
    let mut settings = tls_settings();
    settings.max_version = TlsVersion::Tls13;
    settings
        .cipher_suites
        .insert(0, CipherSuite::Aes128GcmSha256);
    settings.key_shares = vec![NamedGroup::X25519];
    settings.ech_grease = true;
    settings.ech_from_https_records = true;
    settings
}

fn client(identity: &TestIdentity, dns: &DnsServer) -> TestResult<Client> {
    let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
    let resolver = HttpsRecordResolver::from_fn(move |_, port| {
        let upstream = upstream.clone();
        async move { upstream.lookup(STAND_IN_NAME, port).await }
    });
    let profile = ClientProfile::new(ech_tls_settings())
        .with_http2(chromium::v154_http2())
        .with_http3(client_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN.saturating_add(7))
        .https_record_discovery(resolver)
        .build()?)
}

fn ech_acceptor(identity: &TestIdentity, config: &[u8]) -> TestResult<SslAcceptor> {
    let builder = identity.acceptor_builder(H1_ALPN)?;
    let mut keys = SslEchKeys::builder()?;
    keys.add_key(
        true,
        config,
        HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[0].private_key)?,
    )?;
    builder.set_ech_keys(&keys.build())?;
    Ok(builder.build())
}

/// Serves `connections` HTTP/1.1 connections, one response each.
async fn serve(
    listener: TcpListener,
    acceptor: SslAcceptor,
    connections: usize,
) -> TestResult<Vec<Observed>> {
    let mut observed = Vec::new();
    for _ in 0..connections {
        let (mut tcp, _) = timeout(TEST_TIMEOUT, listener.accept()).await??;
        let capture = capture_client_hello(
            &mut tcp,
            tokio::time::Instant::now() + TEST_TIMEOUT,
            CaptureLimits::new(64 * 1024, 64 * 1024, 8),
        )
        .await?;
        let summary = capture.summary()?;
        let prefix = capture
            .records()
            .iter()
            .flat_map(|record| record.wire_bytes().iter().copied())
            .collect();
        let mut tls = SslStream::new(
            Ssl::new(acceptor.context())?,
            Replayed {
                prefix,
                offset: 0,
                inner: tcp,
            },
        )?;
        Pin::new(&mut tls).accept().await?;
        observed.push(Observed {
            outer_server_name: summary
                .server_name()
                .map(|name| String::from_utf8_lossy(name).into_owned()),
            ech_accepted: tls.ssl().ech_accepted(),
            inner_server_name: tls.ssl().servername(NameType::HOST_NAME).map(str::to_owned),
        });
        read_head(&mut tls).await?;
        tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .await?;
        tls.shutdown().await?;
    }
    Ok(observed)
}

struct Replayed {
    prefix: Vec<u8>,
    offset: usize,
    inner: TcpStream,
}

impl AsyncRead for Replayed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let start = self.offset;
            let count = (self.prefix.len() - start).min(buffer.remaining());
            buffer.put_slice(&self.prefix[start..start + count]);
            self.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for Replayed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[tokio::test]
async fn a_known_record_encrypts_the_client_hello_to_the_origin() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity =
            TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), ORIGIN_NAME)?;
        let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
        let rdata = https_rdata(&ech_config_list(std::slice::from_ref(&config)));
        let dns = DnsServer::spawn(move |_| {
            DnsReply::new(DnsAnswer::Records {
                ttl: 300,
                rdata: vec![rdata.clone()],
            })
        })
        .await?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(serve(listener, ech_acceptor(&identity, &config)?, 2));
        let client = client(&identity, &dns)?;

        for path in ["/first", "/second"] {
            let response = client
                .get_negotiated(&format!("https://{ORIGIN_NAME}:{port}{path}"))?
                .send()
                .await?;
            response.into_body().collect().await?;
            // The first connection may or may not see the lookup, depending
            // on how fast the loopback resolver answers; the second one
            // finds it cached.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let observed = server.await??;
        let second = &observed[1];
        assert_eq!(second.outer_server_name.as_deref(), Some(PUBLIC_NAME));
        assert!(second.ech_accepted);
        assert_eq!(second.inner_server_name.as_deref(), Some(ORIGIN_NAME));
        Ok(())
    })
    .await
    .map_err(|_| "ECH test exceeded its deadline")?
}

#[tokio::test]
async fn a_profile_without_the_field_keeps_ech_grease() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity =
            TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), ORIGIN_NAME)?;
        let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
        let rdata = https_rdata(&ech_config_list(std::slice::from_ref(&config)));
        let dns = DnsServer::spawn(move |_| {
            DnsReply::new(DnsAnswer::Records {
                ttl: 300,
                rdata: vec![rdata.clone()],
            })
        })
        .await?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(serve(listener, ech_acceptor(&identity, &config)?, 2));

        let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
        let resolver = HttpsRecordResolver::from_fn(move |_, port| {
            let upstream = upstream.clone();
            async move { upstream.lookup(STAND_IN_NAME, port).await }
        });
        let mut settings = ech_tls_settings();
        settings.ech_from_https_records = false;
        let profile = ClientProfile::new(settings)
            .with_http2(chromium::v154_http2())
            .with_http3(client_settings());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .alt_svc(NonZeroUsize::MIN.saturating_add(7))
            .https_record_discovery(resolver)
            .build()?;

        for path in ["/first", "/second"] {
            let response = client
                .get_negotiated(&format!("https://{ORIGIN_NAME}:{port}{path}"))?
                .send()
                .await?;
            response.into_body().collect().await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        for connection in server.await?? {
            assert_eq!(connection.outer_server_name.as_deref(), Some(ORIGIN_NAME));
            assert!(!connection.ech_accepted);
        }
        Ok(())
    })
    .await
    .map_err(|_| "ECH test exceeded its deadline")?
}
