//! Loopback origins that decrypt Encrypted Client Hello, and the client and
//! HTTPS record that point a client at them.

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
use phantom::{
    Client,
    dns::HttpsRecordResolver,
    profile::{CipherSuite, ClientProfile, NamedGroup, TlsSettings, TlsVersion},
};
use phantom_testkit::{
    dns::{DnsAnswer, DnsReply, DnsServer},
    tls::{CaptureLimits, EchTestKey, capture_client_hello, ech_config},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_btls::SslStream;

use super::tls::{TestIdentity, TestResult, tls_settings};

pub(crate) const TEST_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const ORIGIN_NAME: &str = "localhost";
pub(crate) const STAND_IN_NAME: &str = "origin.test";
pub(crate) const PUBLIC_NAME: &str = "public.phantom.test";

/// What the origin saw on one connection.
#[derive(Debug)]
pub(crate) struct Observed {
    pub(crate) outer_server_name: Option<String>,
    pub(crate) ech_accepted: bool,
    pub(crate) inner_server_name: Option<String>,
}

/// A ServiceMode record at the owner name with `alpn=h2` and `ech`.
pub(crate) fn https_rdata(ech_config_list: &[u8]) -> Vec<u8> {
    https_rdata_with_alpn(&[b"h2"], ech_config_list)
}

/// A ServiceMode record at the owner name with `alpn` and `ech`.
pub(crate) fn https_rdata_with_alpn(alpn: &[&[u8]], ech_config_list: &[u8]) -> Vec<u8> {
    let alpn = alpn
        .iter()
        .flat_map(|id| std::iter::once(id.len() as u8).chain(id.iter().copied()))
        .collect::<Vec<_>>();
    let mut rdata = vec![0x00, 0x01, 0x00, 0x00, 0x01];
    rdata.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
    rdata.extend_from_slice(&alpn);
    rdata.extend_from_slice(&5_u16.to_be_bytes());
    rdata.extend_from_slice(&(ech_config_list.len() as u16).to_be_bytes());
    rdata.extend_from_slice(ech_config_list);
    rdata
}

/// A DNS server that answers every query with `rdata`.
pub(crate) async fn record_server(rdata: Vec<Vec<u8>>) -> TestResult<DnsServer> {
    Ok(DnsServer::spawn(move |_| {
        DnsReply::new(DnsAnswer::Records {
            ttl: 300,
            rdata: rdata.clone(),
        })
    })
    .await?)
}

/// A certificate for the origin and for the configurations' public name,
/// which a server that rejects ECH authenticates as.
pub(crate) fn origin_identity() -> TestResult<TestIdentity> {
    TestIdentity::generate_for_ip_and_dns_names(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &[ORIGIN_NAME, PUBLIC_NAME],
    )
}

/// TLS 1.3 test settings that offer ECH from HTTPS records, as Chrome 154's
/// recipe does.
pub(crate) fn ech_tls_settings() -> TlsSettings {
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

/// A client whose HTTPS record lookups go to `dns` for the stand-in name,
/// since the loopback origin is `localhost`.
pub(crate) fn discovering_client(
    identity: &TestIdentity,
    dns: &DnsServer,
    profile: ClientProfile,
    route: Option<phantom::Route>,
) -> TestResult<Client> {
    let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
    let resolver = HttpsRecordResolver::from_fn(move |_, port| {
        let upstream = upstream.clone();
        async move { upstream.lookup(STAND_IN_NAME, port).await }
    });
    let mut builder = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN.saturating_add(7))
        .https_record_discovery(resolver);
    if let Some(route) = route {
        builder = builder.route(route);
    }
    Ok(builder.build()?)
}

/// An acceptor that selects from `alpn` and decrypts ECH with `key` under
/// the configuration `config`, which it also sends as retry configuration.
pub(crate) fn ech_acceptor(
    identity: &TestIdentity,
    alpn: &'static [u8],
    config_id: u8,
    key: &EchTestKey,
) -> TestResult<SslAcceptor> {
    let builder = identity.acceptor_builder(alpn)?;
    let mut keys = SslEchKeys::builder()?;
    keys.add_key(
        true,
        &ech_config(config_id, key, PUBLIC_NAME),
        HpkeKey::dhkem_p256_sha256(&key.private_key)?,
    )?;
    builder.set_ech_keys(&keys.build())?;
    Ok(builder.build())
}

/// Reads the ClientHello, then completes the server handshake.
pub(crate) async fn handshake(
    tcp: TcpStream,
    acceptor: &SslAcceptor,
) -> TestResult<(Observed, SslStream<Replayed>)> {
    let (mut tls, outer_server_name) = start(tcp, acceptor).await?;
    Pin::new(&mut tls).accept().await?;
    let seen = Observed {
        outer_server_name,
        ech_accepted: tls.ssl().ech_accepted(),
        inner_server_name: tls.ssl().servername(NameType::HOST_NAME).map(str::to_owned),
    };
    Ok((seen, tls))
}

/// Reads the ClientHello, then tries the server handshake. The stream is
/// `None` when the handshake failed, as it may when the server rejects ECH
/// and the client aborts to retry.
pub(crate) async fn try_handshake(
    tcp: TcpStream,
    acceptor: &SslAcceptor,
) -> TestResult<(Observed, Option<SslStream<Replayed>>)> {
    let (mut tls, outer_server_name) = start(tcp, acceptor).await?;
    let completed = matches!(
        tokio::time::timeout(TEST_TIMEOUT, Pin::new(&mut tls).accept()).await,
        Ok(Ok(()))
    );
    let seen = Observed {
        outer_server_name,
        ech_accepted: completed && tls.ssl().ech_accepted(),
        inner_server_name: completed
            .then(|| tls.ssl().servername(NameType::HOST_NAME).map(str::to_owned))
            .flatten(),
    };
    Ok((seen, completed.then_some(tls)))
}

async fn start(
    mut tcp: TcpStream,
    acceptor: &SslAcceptor,
) -> TestResult<(SslStream<Replayed>, Option<String>)> {
    let capture = capture_client_hello(
        &mut tcp,
        tokio::time::Instant::now() + TEST_TIMEOUT,
        CaptureLimits::new(64 * 1024, 64 * 1024, 8),
    )
    .await?;
    let outer_server_name = capture
        .summary()?
        .server_name()
        .map(|name| String::from_utf8_lossy(name).into_owned());
    let prefix = capture
        .records()
        .iter()
        .flat_map(|record| record.wire_bytes().iter().copied())
        .collect();
    let tls = SslStream::new(
        Ssl::new(acceptor.context())?,
        Replayed {
            prefix,
            offset: 0,
            inner: tcp,
        },
    )?;
    Ok((tls, outer_server_name))
}

/// Replays the captured ClientHello records before reading the socket.
pub(crate) struct Replayed {
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
