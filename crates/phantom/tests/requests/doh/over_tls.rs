//! TLS transport with the same independent DNS fixtures used by the DoH tests.

use std::{io, net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use phantom::{
    Client, HttpProtocol,
    dns::{DnsOverTls, DotAddressFamilies, DotConfiguration},
    profile::ClientProfile,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use super::peer::wire::Question;
use crate::support::{
    tls::{TestIdentity, TestResult, accept_tls, read_head, tls_settings},
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const DEADLINE: Duration = Duration::from_secs(5);

async fn read_question(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<Question> {
    let length = usize::from(stream.read_u16().await?);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Question::read(&bytes)
}

async fn reply(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> io::Result<()> {
    stream
        .write_u16(u16::try_from(bytes.len()).map_err(io::Error::other)?)
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

#[tokio::test]
async fn public_resolvers_share_tls_across_cname_addresses_and_https_records() -> TestResult<()> {
    let identity = TestIdentity::generate_for_dns("resolver.test")?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let configuration = DotConfiguration::new(
        "resolver.test",
        [listener.local_addr()?],
        DotAddressFamilies::Ipv4Only,
        DEADLINE,
        NonZeroUsize::MIN,
    );
    let dot = DnsOverTls::builder(tls_settings(), configuration)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?;
    let acceptor = identity.acceptor(b"\x03dot")?;
    let mut dns = ConnectionPeer::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        let question = read_question(&mut stream).await?;
        assert_eq!(question.name, "application.test");
        reply(&mut stream, &question.cname("target.test", 30)?).await?;
        let question = read_question(&mut stream).await?;
        assert_eq!(question.name, "target.test");
        reply(
            &mut stream,
            &question.addresses(&[Ipv4Addr::LOCALHOST.into()], 60)?,
        )
        .await?;
        let question = read_question(&mut stream).await?;
        assert_eq!(question.name, "_8443._https.application.test");
        assert_eq!(question.kind, 65);
        reply(&mut stream, &question.https(30, &[0, 1, 0])?).await?;
        Ok(())
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!(
        "http://application.test:{}/application",
        listener.local_addr()?.port()
    );
    let mut origin = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        assert!(
            read_head(&mut stream)
                .await?
                .starts_with(b"GET /application HTTP/1.1\r\n")
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
        stream.flush().await?;
        Ok(())
    });
    let primary = timeout(DEADLINE, async {
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .dns_resolver(dot.address_resolver())
            .no_dns_cache()
            .build()?;
        let response = client.get(HttpProtocol::Http1, &url)?.send().await?;
        assert_eq!(
            response.into_body().collect_with_limit(2).await?.as_ref(),
            b"ok"
        );
        let records = dot
            .clone()
            .https_record_resolver()
            .lookup("application.test", 8443)
            .await?;
        assert_eq!(records.answers().len(), 1);
        (&mut dns).await??;
        (&mut origin).await??;
        TestResult::Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|result| result);
    let cleanup = finish_with_cleanup(dns.shutdown().await, origin.shutdown().await);
    finish_with_cleanup(primary, cleanup)
}

#[test]
fn public_builder_rejects_unbounded_work_and_debug_omits_identity() -> TestResult<()> {
    let address = "127.0.0.1:853".parse::<std::net::SocketAddr>()?;
    let configuration = || {
        DotConfiguration::new(
            "resolver.secret.test",
            [address],
            DotAddressFamilies::DualIpv6First,
            DEADLINE,
            NonZeroUsize::MIN,
        )
    };
    let debug = format!("{:?}", DnsOverTls::builder(tls_settings(), configuration()));
    assert!(!debug.contains("resolver.secret.test"));
    assert!(!debug.contains("127.0.0.1"));
    let too_many = DotConfiguration::new(
        "resolver.test",
        ["127.0.0.1:853".parse()?],
        DotAddressFamilies::Ipv4Only,
        DEADLINE,
        NonZeroUsize::new(32768).ok_or("limit")?,
    );
    assert_eq!(
        DnsOverTls::builder(tls_settings(), too_many)
            .build()
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    let invalid_root =
        DnsOverTls::builder(tls_settings(), configuration()).add_root_certificate_der(vec![0]);
    assert!(invalid_root.build().is_err());
    Ok(())
}
