use std::{fmt, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use btls::{
    ssl::{
        AlpnError, SessionPolicyBinding, SessionTransferPolicy, SslContext, SslFiletype, SslMethod,
        SslVerifyMode, select_next_proto,
    },
    x509::X509,
};
use phantom_quic_btls::{
    ApplicationState, HandshakeData, PeerIdentity, QuicClientConfig, QuicServerConfig,
    QuicSessionTicketCacheOwner, ServerHandshakeData,
};
use tokio::time::timeout;

use super::{APPLICATION, HOST, TestResult};

const DEADLINE: Duration = Duration::from_secs(15);
const REQUEST: &[u8] = b"Q1 UDP request";
const RESPONSE: &[u8] = b"Q1 UDP response";

pub(super) struct Client {
    pub(super) config: QuicClientConfig,
    pub(super) context: SslContext,
    pub(super) owner: QuicSessionTicketCacheOwner,
    pub(super) binding: SessionPolicyBinding,
}

impl Client {
    pub(super) fn new(owner_key: [u8; 32]) -> TestResult<Self> {
        let mut builder = SslContext::builder(SslMethod::tls())?;
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_ca_file(fixture("root-ca.pem"))?;
        QuicClientConfig::enable_session_resumption(&mut builder)?;
        let context = builder.build();
        let config = QuicClientConfig::new(context.clone())
            .with_tls_profile(&phantom_profile::browser::chrome::v154_quic_tls())?
            .with_isolated_session_cache()
            .without_early_data();

        let owner = config
            .session_ticket_cache()
            .and_then(|control| control.upgrade())
            .ok_or("client cache absent")?;

        let binding = owner.bind_transfer_policy(
            HOST,
            SessionTransferPolicy::new(b"Q1 UDP transfer policy", &[0, 0], None, &owner_key)?,
        )?;
        Ok(Self {
            config,
            context,
            owner,
            binding,
        })
    }
}

pub(super) enum Publication {
    Store,
    Hold,
}

pub(super) struct Observed {
    pub(super) client: HandshakeData,
    pub(super) server: ServerHandshakeData,
    pub(super) certificates: Vec<Vec<u8>>,
}

pub(super) struct Peers {
    client: quinn::Endpoint,
    server: quinn::Endpoint,
    address: SocketAddr,
    version: u32,
    pub(super) leaf_certificate: Vec<u8>,
}

impl Peers {
    pub(super) fn new(version: u32) -> TestResult<Self> {
        let mut builder = SslContext::builder(SslMethod::tls())?;
        builder.set_certificate_chain_file(fixture("cert.pem"))?;
        builder.set_private_key_file(fixture("key.pem"), SslFiletype::PEM)?;
        builder.set_alpn_select_callback(|_, offered| {
            select_next_proto(b"\x02h3", offered).ok_or(AlpnError::NOACK)
        });

        let crypto = QuicServerConfig::new(builder.build());
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(1u32.into());
        transport.max_concurrent_uni_streams(0u32.into());
        server_config.transport_config(Arc::new(transport));

        let server = endpoint(version, Some(server_config))?;
        let address = server.local_addr()?;
        let client = endpoint(version, None)?;

        let certificate = std::fs::read(fixture("cert.pem"))?;
        let leaf_certificate = X509::from_pem(&certificate)?.to_der()?;
        Ok(Self {
            client,
            server,
            address,
            version,
            leaf_certificate,
        })
    }

    pub(super) async fn exchange(
        &self,
        client: &Client,
        publication: Publication,
    ) -> TestResult<Observed> {
        let result = match timeout(DEADLINE, self.exchange_inner(client, publication)).await {
            Ok(result) => result,
            Err(error) => Err(error.into()),
        };
        with_cleanup(result, self.idle().await)
    }

    async fn exchange_inner(
        &self,
        client: &Client,
        publication: Publication,
    ) -> TestResult<Observed> {
        let application = ApplicationState::new();
        let mut config =
            quinn::ClientConfig::new(Arc::new(client.config.with_application_state(&application)));
        config.version(self.version);
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(0u32.into());
        transport.max_concurrent_uni_streams(0u32.into());
        config.transport_config(Arc::new(transport));

        let connecting = self.client.connect_with(config, self.address, HOST)?;
        let connecting = match connecting.into_0rtt() {
            Err(connecting) => connecting,
            Ok((connection, _accepted)) => {
                connection.close(0u32.into(), b"unexpected early data");
                return Err("client unexpectedly obtained early-data keys".into());
            }
        };

        let client_exchange = async {
            let connection = connecting.await?;
            let (mut send, mut receive) = connection.open_bi().await?;
            send.write_all(REQUEST).await?;
            send.finish()?;
            let response = receive.read_to_end(RESPONSE.len()).await?;
            if response != RESPONSE {
                return Err("client received a different response marker".into());
            }

            Ok::<_, Box<dyn std::error::Error>>(connection)
        };
        let server_exchange = async {
            let incoming = self
                .server
                .accept()
                .await
                .ok_or("server endpoint stopped")?;
            let connection = incoming.await?;
            let (mut send, mut receive) = connection.accept_bi().await?;
            let request = receive.read_to_end(REQUEST.len()).await?;
            if request != REQUEST {
                return Err("server received a different request marker".into());
            }

            send.write_all(RESPONSE).await?;
            send.finish()?;
            if send.stopped().await?.is_some() {
                return Err("client stopped the response stream".into());
            }
            Ok::<_, Box<dyn std::error::Error>>(connection)
        };
        let (client_connection, server_connection) =
            tokio::try_join!(client_exchange, server_exchange)?;
        let connections = Connections {
            client: client_connection,
            server: server_connection,
        };

        let client_data = connections
            .client
            .handshake_data()
            .ok_or("client handshake data absent")?
            .downcast::<HandshakeData>()
            .map_err(|_| "client handshake data type mismatch")?;
        let server_data = connections
            .server
            .handshake_data()
            .ok_or("server handshake data absent")?
            .downcast::<ServerHandshakeData>()
            .map_err(|_| "server handshake data type mismatch")?;
        let identity = connections
            .client
            .peer_identity()
            .ok_or("verified peer identity absent")?
            .downcast::<PeerIdentity>()
            .map_err(|_| "verified peer identity type mismatch")?;
        if client_data.protocol() != b"h3" || server_data.protocol() != b"h3" {
            return Err("negotiated ALPN differs from h3".into());
        }

        if server_data.server_name() != Some(HOST) {
            return Err("server received a different SNI name".into());
        }

        if server_data.early_data_accepted() != Some(false) {
            return Err("completed server handshake did not reject early data".into());
        }

        if matches!(publication, Publication::Store) {
            if !application.store(APPLICATION) {
                return Err("source application state was not stored".into());
            }
            while !client.config.has_ticket_for(HOST) {
                tokio::task::yield_now().await;
            }
        }

        // Hold never publishes replacement tickets, so exhaustion cannot be
        // hidden by tickets issued during the imported-ticket handshakes.
        Ok(Observed {
            client: *client_data,
            server: *server_data,
            certificates: identity.certificates().to_vec(),
        })
    }

    async fn idle(&self) -> TestResult {
        timeout(DEADLINE, async {
            tokio::join!(self.client.wait_idle(), self.server.wait_idle());
        })
        .await?;
        Ok(())
    }

    pub(super) async fn shutdown(&self) -> TestResult {
        self.client.close(0u32.into(), b"test finished");
        self.server.close(0u32.into(), b"test finished");
        self.idle().await
    }
}

impl Drop for Peers {
    fn drop(&mut self) {
        self.client.close(0u32.into(), b"test dropped");
        self.server.close(0u32.into(), b"test dropped");
    }
}

struct Connections {
    client: quinn::Connection,
    server: quinn::Connection,
}

impl Drop for Connections {
    fn drop(&mut self) {
        self.client.close(0u32.into(), b"exchange finished");
        self.server.close(0u32.into(), b"exchange finished");
    }
}

fn endpoint(version: u32, server: Option<quinn::ServerConfig>) -> TestResult<quinn::Endpoint> {
    let socket = phantom_testkit::udp::bind("127.0.0.1:0".parse()?)?;
    if !socket.local_addr()?.ip().is_loopback() {
        return Err("test socket was not bound to loopback".into());
    }

    let mut config = quinn::EndpointConfig::default();
    config.supported_versions(vec![version]);
    config.compatible_versions(Vec::new());
    Ok(quinn::Endpoint::new(
        config,
        server,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?)
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/btls/test")
        .join(name)
}

pub(super) fn with_cleanup<T>(result: TestResult<T>, cleanup: TestResult) -> TestResult<T> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(CleanupError { operation, cleanup }.into()),
    }
}

#[derive(Debug)]
struct CleanupError {
    operation: Box<dyn std::error::Error>,
    cleanup: Box<dyn std::error::Error>,
}

impl fmt::Display for CleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; peer cleanup failed: {}",
            self.operation, self.cleanup
        )
    }
}

impl std::error::Error for CleanupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.operation.as_ref())
    }
}
