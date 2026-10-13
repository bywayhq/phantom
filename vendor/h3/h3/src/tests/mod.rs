// This is to avoid an import loop:
// h3 tests depend on having private access to the crate.
// They must be part of the crate so as not to break privacy.
// They also depend on h3_quinn which depends on the crate.
// Having a dev-dependency on h3_quinn would work as far as cargo is
// concerned, but quic traits wouldn't match between the "h3" crate that
// comes before h3_quinn and the one that comes after and runs the tests
#[allow(unexpected_cfgs)]
#[path = "../../../h3-quinn/src/lib.rs"]
mod h3_quinn;

mod connection;
mod qpack_request;
mod request;
mod socket;

use std::{
    convert::TryInto,
    io,
    net::{Ipv6Addr, ToSocketAddrs, UdpSocket},
    sync::Arc,
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::Request;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::quic;
use h3_quinn::{quinn::TransportConfig, Connection};

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_test_writer()
        .try_init();
}

/// This accepts an incoming request. After the bidirectional stream is started it will not poll the
/// connection or receive further requests until the first headers are received.
/// Only use this for testing purposes.
async fn get_stream_blocking<C: quic::Connection<B>, B: Buf>(
    incoming: &mut crate::server::Connection<C, B>,
) -> Option<(Request<()>, crate::server::RequestStream<C::BidiStream, B>)> {
    let request_resolver = incoming.accept().await.ok()??;
    let (request, stream) = request_resolver.resolve_request().await.ok()?;
    Some((request, stream))
}

// Keep this standalone vendor harness independent of the first-party testkit.
// Mirror its ephemeral-port rule locally instead of adding a workspace dependency.
fn bind_loopback_socket() -> io::Result<UdpSocket> {
    retry_reserved_ports(cfg!(windows), || UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)))
}

// Three additional attempts let Windows advance past a transient reserved-port
// refusal. Only WSAENOBUFS (10055) is retried; all other errors are returned as-is.
const RESERVED_PORT_RETRIES: usize = 3;

fn retry_reserved_ports<T>(
    windows: bool,
    mut bind: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut retries = 0;
    loop {
        match bind() {
            Err(error)
                if windows
                    && error.raw_os_error() == Some(10_055)
                    && retries < RESERVED_PORT_RETRIES =>
            {
                retries += 1;
            }
            result => return result,
        }
    }
}

pub struct Pair {
    port: u16,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    config: Arc<TransportConfig>,
}

impl Default for Pair {
    fn default() -> Self {
        let (cert, key) = build_certs();
        Self {
            cert,
            key,
            port: 0,
            config: Arc::new(TransportConfig::default()),
        }
    }
}

impl Pair {
    pub fn with_timeout(&mut self, duration: Duration) {
        Arc::get_mut(&mut self.config)
            .unwrap()
            .max_idle_timeout(Some(
                duration.try_into().expect("idle timeout duration invalid"),
            ))
            .initial_rtt(Duration::from_millis(10));
    }

    pub fn server_inner(&mut self) -> h3_quinn::Endpoint {
        let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
        .unwrap();
        crypto.max_early_data_size = u32::MAX;
        crypto.alpn_protocols = vec![b"h3".to_vec()];

        let mut server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(crypto).unwrap(),
        ));
        server_config.transport = self.config.clone();
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            bind_loopback_socket().unwrap(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();

        self.port = endpoint.local_addr().unwrap().port();

        endpoint
    }

    pub fn server(&mut self) -> Server {
        let endpoint = self.server_inner();
        Server { endpoint }
    }

    fn client_endpoint(&self) -> quinn::Endpoint {
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.add(self.cert.clone()).unwrap();
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
        crypto.enable_early_data = true;
        crypto.alpn_protocols = vec![b"h3".to_vec()];

        let client_config = h3_quinn::quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).unwrap(),
        ));

        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            bind_loopback_socket().unwrap(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    pub async fn client_inner(&self) -> quinn::Connection {
        let addr = (Ipv6Addr::LOCALHOST, self.port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        self.client_endpoint()
            .connect(addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    }

    pub async fn client(&self) -> h3_quinn::Connection {
        Connection::new(self.client_inner().await)
    }
}

pub struct Server {
    pub endpoint: h3_quinn::Endpoint,
}

impl Server {
    pub async fn next(&mut self) -> impl quic::Connection<Bytes> {
        Connection::new(self.endpoint.accept().await.unwrap().await.unwrap())
    }
}

pub fn build_certs() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (
        cert.cert.into(),
        PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
    )
}
