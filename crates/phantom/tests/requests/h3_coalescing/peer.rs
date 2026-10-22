use std::{net::SocketAddr, sync::Arc};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use futures_util::{StreamExt, stream::FuturesUnordered};
use h3::ext::OrderedHeaders;
use http::{Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_btls::SslStream;

use crate::support::{
    h3 as h3_support, shared_port,
    tls::{H1_ALPN, TestIdentity, TestResult, accept_tls_stream, read_head},
};

use super::{DONOR, OTHER};

#[derive(Debug)]
pub(super) struct Observation {
    pub(super) connection: Option<usize>,
    pub(super) stream: Option<u64>,
    pub(super) method: String,
    pub(super) authority: String,
    pub(super) path: String,
    pub(super) fields: Vec<(String, Vec<u8>)>,
}

pub(super) struct Peer {
    pub(super) address: SocketAddr,
    pub(super) endpoint: quinn::Endpoint,
    listener: TcpListener,
    acceptor: SslAcceptor,
}

impl Peer {
    pub(super) async fn bind(tcp: &TestIdentity, quic: &TestIdentity) -> TestResult<Self> {
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(quic.leaf_der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(quic.private_key_der().to_vec())),
            )?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        for port in shared_port::candidates() {
            let address = SocketAddr::from(([127, 0, 0, 1], port));
            let listener = match TcpListener::bind(address).await {
                Ok(listener) => listener,
                Err(error) if shared_port::is_unavailable(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let endpoint = match h3_support::quic_server(config.clone(), address) {
                Ok(endpoint) => endpoint,
                Err(error) if shared_port::is_unavailable(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            return Ok(Self {
                address,
                endpoint,
                listener,
                acceptor: tcp.acceptor(H1_ALPN)?,
            });
        }
        Err("no loopback port available for the coalescing TCP/UDP origin".into())
    }

    pub(super) async fn serve_tcp(
        &self,
        mut stop: watch::Receiver<bool>,
    ) -> TestResult<Vec<Observation>> {
        let mut records = Vec::new();
        loop {
            let (tcp, _) = tokio::select! {
                _ = stop.wait_for(|stopped| *stopped) => return Ok(records),
                accepted = self.listener.accept() => accepted?,
            };
            let (mut stream, record) = self.read_tcp_request(tcp).await?;
            self.validate(&record.authority, &record.path, &record.method)?;
            let advertisement = if record.authority == format!("{DONOR}:{}", self.address.port())
                && record.path == "/learn"
            {
                format!("Alt-Svc: h3=\":{}\"; ma=60\r\n", self.address.port())
            } else {
                String::new()
            };
            records.push(record);
            if records.len() > 3 {
                return Err("coalescing fixture received too many HTTP/1 requests".into());
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n{advertisement}\r\nok"
            );
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
        }
    }

    pub(super) async fn accept_tcp_request(
        &self,
    ) -> TestResult<(SslStream<TcpStream>, Observation)> {
        let (tcp, _) = self.listener.accept().await?;
        self.read_tcp_request(tcp).await
    }

    async fn read_tcp_request(
        &self,
        tcp: TcpStream,
    ) -> TestResult<(SslStream<TcpStream>, Observation)> {
        let mut stream = accept_tls_stream(tcp, self.acceptor.clone()).await?;
        let head = read_head(&mut stream).await?;
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        if !request.parse(&head)?.is_complete() {
            return Err("incomplete coalescing HTTP/1 request head".into());
        }
        let authority = request
            .headers
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case("host"))
            .ok_or("coalescing HTTP/1 request omitted Host")?;
        let record = Observation {
            connection: None,
            stream: None,
            method: request
                .method
                .ok_or("coalescing HTTP/1 request omitted its method")?
                .to_owned(),
            authority: std::str::from_utf8(authority.value)?.to_owned(),
            path: request
                .path
                .ok_or("coalescing HTTP/1 request omitted its target")?
                .to_owned(),
            fields: request
                .headers
                .iter()
                .map(|field| (field.name.to_ascii_lowercase(), field.value.to_vec()))
                .collect(),
        };
        Ok((stream, record))
    }

    pub(super) async fn serve_h3(
        &self,
        mut stop: watch::Receiver<bool>,
    ) -> TestResult<Vec<Observation>> {
        let mut connections = FuturesUnordered::new();
        let mut records = Vec::new();
        let mut accepted = 0;
        loop {
            tokio::select! {
                _ = async { stop.wait_for(|stopped| *stopped).await.map(|_| ()) } => {
                    while let Some(completed) = connections.next().await {
                        records.extend(completed?);
                    }
                    return Ok(records);
                }
                incoming = self.endpoint.accept() => {
                    let incoming = incoming.ok_or("coalescing QUIC endpoint closed early")?;
                    accepted += 1;
                    if accepted > 3 {
                        return Err("coalescing fixture received too many QUIC connections".into());
                    }
                    connections.push(self.serve_connection(incoming, stop.clone()));
                }
                completed = connections.next(), if !connections.is_empty() => {
                    records.extend(completed.ok_or("coalescing QUIC owner disappeared")??);
                }
            }
        }
    }

    async fn serve_connection(
        &self,
        incoming: quinn::Incoming,
        mut stop: watch::Receiver<bool>,
    ) -> TestResult<Vec<Observation>> {
        let connection = tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => return Ok(Vec::new()),
            connection = async { incoming.await } => connection?,
        };
        let identity = connection.stable_id();
        let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
        let mut records = Vec::new();
        loop {
            let accepted = tokio::select! {
                _ = stop.wait_for(|stopped| *stopped) => return Ok(records),
                accepted = h3.accept() => match accepted {
                    Err(h3::error::ConnectionError::Remote(h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code }, ..))
                        if error_code == h3::error::Code::H3_NO_ERROR.value() => return Ok(records),
                    accepted => accepted?,
                },
            };
            let Some(resolver) = accepted else {
                return Ok(records);
            };
            let (request, mut stream) = resolver.resolve_request().await?;
            let authority = request
                .uri()
                .authority()
                .ok_or("coalescing HTTP/3 request omitted authority")?
                .to_string();
            let path = request.uri().path().to_owned();
            self.validate(&authority, &path, request.method().as_str())?;
            if stream.recv_data().await?.is_some() {
                return Err("coalescing GET unexpectedly carried a request body".into());
            }
            let fields = request
                .extensions()
                .get::<OrderedHeaders>()
                .ok_or("coalescing HTTP/3 request omitted decoded field order")?
                .as_slice()
                .iter()
                .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
                .collect();
            records.push(Observation {
                connection: Some(identity),
                stream: Some(stream.id().into_inner()),
                method: request.method().to_string(),
                authority,
                path,
                fields,
            });
            if records.len() > 3 {
                return Err("coalescing fixture received too many HTTP/3 requests".into());
            }
            stream
                .send_response(Response::builder().status(StatusCode::OK).body(())?)
                .await?;
            stream.send_data(Bytes::from_static(b"ok")).await?;
            stream.finish().await?;
        }
    }

    fn validate(&self, authority: &str, path: &str, method: &str) -> TestResult<()> {
        let donor = format!("{DONOR}:{}", self.address.port());
        let other = format!("{OTHER}:{}", self.address.port());
        let owned_target = matches!((authority, path), (host, "/learn" | "/settled") if host == donor)
            || authority == other && path == "/first";
        if method != "GET" || !owned_target {
            return Err(
                format!("unexpected coalescing request: {method} {authority}{path}").into(),
            );
        }
        Ok(())
    }
}
