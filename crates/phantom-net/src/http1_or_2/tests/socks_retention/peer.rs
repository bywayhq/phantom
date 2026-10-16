use std::{io, net::Ipv4Addr, pin::Pin, time::Duration};

use btls::ssl::{Ssl, SslAcceptor};
use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;
use phantom_profile::browser::firefox;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_btls::SslStream;

use crate::{
    host_resolver::HostResolver,
    http1_or_2::{Http1Or2Connection, Http1Or2TlsConnector},
    http2::Http2TlsConnector,
    proxy::Socks5Auth,
    request::{OriginForm, RequestHeader},
    route::{DirectTlsSetup, Endpoint, OriginRoute, Socks5Target, TcpRoute},
    tcp::{AddressFamilyMemory, SlowerConnection},
    tls::test_support::{TEST_SERVER_NAME, TestIdentity, TestResult},
};

pub(super) const WAIT: Duration = Duration::from_secs(5);
pub(super) type Opened = (
    Http1Or2Connection,
    Option<SlowerConnection<Http1Or2Connection>>,
);

pub(super) struct Connectors {
    pub(super) exact: Http2TlsConnector,
    pub(super) negotiated: Http1Or2TlsConnector,
}

impl Connectors {
    pub(super) fn new(identity: &TestIdentity, early: bool) -> TestResult<Self> {
        let mut tls = firefox::v157_tcp_tls();
        tls.tcp_early_data = early;
        let mut tcp = firefox::v157_tcp();
        tcp.address_selection =
            phantom_profile::TcpAddressSelection::Backup(phantom_profile::TcpBackupConnection {
                delay: Duration::from_millis(1),
                known_family_backup_timeout: Some(Duration::from_secs(1)),
            });
        let exact = Http2TlsConnector::new_with_additional_roots(
            &tls,
            &firefox::v157_http2(),
            [identity.root_der()],
        )?
        .with_tcp_settings(&tcp);
        Ok(Self {
            negotiated: Http1Or2TlsConnector::from_http2(&exact)?,
            exact,
        })
    }

    pub(super) fn with_resolver(mut self, resolver: HostResolver) -> TestResult<Self> {
        self.exact = self.exact.with_host_resolver(resolver);
        self.negotiated = Http1Or2TlsConnector::from_http2(&self.exact)?;
        Ok(self)
    }

    pub(super) async fn connect(
        &self,
        exact: bool,
        origin: OriginRoute<'_>,
        family: &AddressFamilyMemory,
    ) -> TestResult<Opened> {
        if exact {
            let (connection, slower) = self.exact.connect_socks_retaining(origin, family).await?;
            Ok((
                Http1Or2Connection::Http2(connection),
                slower.map(|slower| {
                    SlowerConnection::new(slower.progress(), async move {
                        slower.finish().await.map(Http1Or2Connection::Http2)
                    })
                }),
            ))
        } else {
            Ok(self
                .negotiated
                .connect_socks_retaining(origin, family)
                .await?)
        }
    }
}

pub(super) fn origin(host: &str, port: u16, remote: bool) -> OriginRoute<'_> {
    let target = Endpoint {
        host: if remote {
            TEST_SERVER_NAME
        } else {
            "127.0.0.1"
        },
        port: 443,
    };
    OriginRoute::Tls {
        tcp: TcpRoute::Socks5 {
            proxy: Endpoint { host, port },
            target: if remote {
                Socks5Target::RemoteDns(target)
            } else {
                Socks5Target::LocalDns(target)
            },
            auth: Socks5Auth::None,
        },
        server_name: TEST_SERVER_NAME,
        setup: DirectTlsSetup::Default,
    }
}

pub(super) async fn negotiate(listener: &TcpListener, remote: bool) -> TestResult<TcpStream> {
    let (mut stream, _) = listener.accept().await?;
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await?;
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    assert_eq!(head, [5, 1, 0, if remote { 3 } else { 1 }]);
    if remote {
        let length = stream.read_u8().await?;
        let mut host = vec![0; usize::from(length)];
        stream.read_exact(&mut host).await?;
        assert_eq!(host, TEST_SERVER_NAME.as_bytes());
    } else {
        let mut host = [0; 4];
        stream.read_exact(&mut host).await?;
        assert_eq!(host, Ipv4Addr::LOCALHOST.octets());
    }
    assert_eq!(stream.read_u16().await?, 443);
    Ok(stream)
}

pub(super) async fn reply(stream: &mut TcpStream) -> io::Result<()> {
    // BND.ADDR is unrelated to the target's family memory.
    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 2, 0, 81]).await
}

pub(super) async fn tls(
    stream: TcpStream,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let mut stream = SslStream::new(Ssl::new(acceptor.context())?, stream)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

pub(super) async fn closed(stream: &mut TcpStream) -> TestResult<()> {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        other => Err(format!("unused SOCKS negotiation was not canceled: {other:?}").into()),
    }
}

pub(super) async fn send(connection: &Http1Or2Connection, path: &str) -> TestResult<()> {
    let headers = vec![RequestHeader::new("x-current", "owner")];
    match connection {
        Http1Or2Connection::Http1(connection) => {
            let mut headers = vec![RequestHeader::new("Host", TEST_SERVER_NAME)];
            headers.push(RequestHeader::new("x-current", "owner"));
            let response = connection
                .send_request(
                    Method::POST,
                    OriginForm::parse(path)?,
                    headers,
                    Some(Bytes::from_static(b"current-body")),
                )
                .await?;
            assert_eq!(response.status(), 204);
            assert!(response.into_body().collect().await?.to_bytes().is_empty());
        }
        Http1Or2Connection::Http2(connection) => {
            let response = connection
                .send_request(
                    Method::POST,
                    TEST_SERVER_NAME,
                    OriginForm::parse(path)?,
                    headers,
                    Some(Bytes::from_static(b"current-body")),
                )
                .await?;
            assert_eq!(response.status(), 204);
            assert!(response.into_body().collect().await?.to_bytes().is_empty());
        }
    }
    Ok(())
}

pub(super) async fn serve_h1<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    path: &str,
) -> TestResult<()> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 4096 {
            return Err("request head exceeded fixture bound".into());
        }
        head.push(stream.read_u8().await?);
    }
    assert_eq!(head, format!("POST {path} HTTP/1.1\r\nHost: {TEST_SERVER_NAME}\r\nx-current: owner\r\nContent-Length: 12\r\n\r\n").as_bytes());
    let mut body = [0; 12];
    stream.read_exact(&mut body).await?;
    assert_eq!(&body, b"current-body");
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        .await?;
    stream.shutdown().await?;
    Ok(())
}

pub(super) async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    path: &str,
) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection.accept().await.ok_or("missing H2 request")??;
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri().path(), path);
    assert_eq!(
        request.uri().authority().map(|a| a.as_str()),
        Some(TEST_SERVER_NAME)
    );
    assert_eq!(request.headers()["x-current"], "owner");
    assert!(!request.headers().contains_key("proxy-authorization"));
    let handled = async {
        let mut body = request.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            body.flow_control().release_capacity(chunk.len())?;
            bytes.extend_from_slice(&chunk);
        }
        assert_eq!(bytes, b"current-body");
        respond.send_response(http::Response::builder().status(204).body(())?, true)?;
        TestResult::Ok(())
    };
    let drained = async {
        if let Some(request) = connection.accept().await {
            request?;
            return Err("unexpected replay on retained H2 connection".into());
        }
        TestResult::Ok(())
    };
    tokio::try_join!(handled, drained)?;
    Ok(())
}
