//! Bounded native QUIC handshakes using the existing authenticated test issuer.

use std::io::Cursor;

use btls::ssl::{
    AlpnError, SessionPolicyBinding, SessionTransferPolicy, SslContext, SslFiletype, SslMethod,
    SslVerifyMode, select_next_proto,
};
use phantom_quic_btls::{
    ApplicationState, HandshakeData, PeerIdentity, QuicClientConfig, QuicServerConfig,
    QuicSessionTicketCacheOwner, ServerHandshakeData,
};
use quinn_proto::{Side, crypto, transport_parameters::TransportParameters};

use super::{Arc, TestResult};

pub(super) const HOST: &str = "foobar.com";
const VERSION: u32 = 0x0000_0001;

fn fixture(name: &str) -> String {
    format!(
        "{}/../../vendor/btls/test/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn policy() -> Result<SessionTransferPolicy, btls::ssl::SessionTransferError> {
    SessionTransferPolicy::new(b"mixed real QUIC policy", &[0, 0], None, &[37; 32])
}

pub(super) struct Fixture {
    pub(super) config: QuicClientConfig,
    pub(super) context: SslContext,
    pub(super) owner: QuicSessionTicketCacheOwner,
    pub(super) binding: SessionPolicyBinding,
    server: Arc<QuicServerConfig>,
}

impl Fixture {
    pub(super) fn new() -> TestResult<Self> {
        let mut context = SslContext::builder(SslMethod::tls())?;
        context.set_verify(SslVerifyMode::PEER);
        context.set_ca_file(fixture("root-ca.pem"))?;
        QuicClientConfig::enable_session_resumption(&mut context)?;
        let context = context.build();
        let config = QuicClientConfig::new(context.clone())
            .with_tls_profile(&phantom_profile::browser::chrome::v154_quic_tls())?
            .with_isolated_session_cache()
            .without_early_data();
        let mut server = SslContext::builder(SslMethod::tls())?;
        server.set_certificate_chain_file(fixture("cert.pem"))?;
        server.set_private_key_file(fixture("key.pem"), SslFiletype::PEM)?;
        server.set_alpn_select_callback(|_, offered| {
            select_next_proto(b"\x02h3", offered).ok_or(AlpnError::NOACK)
        });
        Self::bind(
            config,
            context,
            Arc::new(QuicServerConfig::new(server.build())),
        )
    }

    fn bind(
        config: QuicClientConfig,
        context: SslContext,
        server: Arc<QuicServerConfig>,
    ) -> TestResult<Self> {
        let owner = config
            .session_ticket_cache()
            .and_then(|cache| cache.upgrade())
            .ok_or("QUIC cache owner absent")?;
        let binding = owner.bind_transfer_policy(HOST, policy()?)?;
        Ok(Self {
            config,
            context,
            owner,
            binding,
            server,
        })
    }

    pub(super) fn fork_empty(&self) -> TestResult<Self> {
        Self::bind(
            self.config.with_isolated_session_cache(),
            self.context.clone(),
            Arc::clone(&self.server),
        )
    }

    pub(super) fn pending_ticket(&self) -> TestResult<ApplicationState> {
        let application = ApplicationState::new();
        let completed = self.handshake(
            &self
                .config
                .without_ticket_offers()
                .with_application_state(&application),
        )?;
        assert!(!completed.0.session_resumed());
        assert!(!completed.1.session_resumed());
        Ok(application)
    }

    pub(super) fn seed(&self, value: &[u8]) -> TestResult<()> {
        let application = self.pending_ticket()?;
        assert!(application.store(value));
        assert!(self.count() > 0);
        Ok(())
    }

    pub(super) fn resume(&self) -> TestResult<()> {
        let count = self.count();
        assert!(count > 0);
        // New tickets remain private in this never-published handle, so they
        // cannot hide reuse of an old single-use ticket.
        let application = ApplicationState::new();
        let completed = self.handshake(&self.config.with_application_state(&application))?;
        assert!(completed.0.session_resumed());
        assert!(completed.1.session_resumed());
        assert_eq!(self.count(), count - 1);
        Ok(())
    }

    pub(super) fn count(&self) -> usize {
        self.owner.freeze().retained_count()
    }

    fn handshake(
        &self,
        config: &QuicClientConfig,
    ) -> TestResult<(HandshakeData, ServerHandshakeData)> {
        use crypto::{ClientConfig as _, ServerConfig as _};

        // The existing crypto peers use a parsed initial source CID. No ticket,
        // policy authority, or remembered server parameters are fabricated.
        let parameters = |side| TransportParameters::read(side, &mut Cursor::new([0x0f, 1, 1]));
        let mut client = Arc::new(config.without_early_data()).start_session(
            VERSION,
            HOST,
            &parameters(Side::Client)?,
        )?;
        let mut server =
            Arc::clone(&self.server).start_session(VERSION, &parameters(Side::Server)?);
        for round in 0..32 {
            let mut moved = false;
            for flight in 0..16 {
                let mut bytes = Vec::new();
                let keys = client.write_handshake(&mut bytes);
                if !bytes.is_empty() {
                    server.read_handshake(&bytes)?;
                    moved = true;
                }
                if keys.is_none() && bytes.is_empty() {
                    break;
                }
                if flight == 15 {
                    return Err("client flight bound exceeded".into());
                }
            }
            for flight in 0..16 {
                let mut bytes = Vec::new();
                let keys = server.write_handshake(&mut bytes);
                if !bytes.is_empty() {
                    client.read_handshake(&bytes)?;
                    moved = true;
                }
                if keys.is_none() && bytes.is_empty() {
                    break;
                }
                if flight == 15 {
                    return Err("server flight bound exceeded".into());
                }
            }
            if !moved {
                assert!(!client.is_handshaking());
                assert!(!server.is_handshaking());
                assert!(client.early_crypto().is_none());
                assert!(server.early_crypto().is_none());
                assert_eq!(client.early_data_accepted(), Some(false));
                let client_data = client
                    .handshake_data()
                    .ok_or("client handshake data absent")?
                    .downcast::<HandshakeData>()
                    .map_err(|_| "client handshake data type")?;
                let server_data = server
                    .handshake_data()
                    .ok_or("server handshake data absent")?
                    .downcast::<ServerHandshakeData>()
                    .map_err(|_| "server handshake data type")?;
                let identity = client
                    .peer_identity()
                    .ok_or("verified peer identity absent")?
                    .downcast::<PeerIdentity>()
                    .map_err(|_| "peer identity type")?;
                assert!(!identity.certificates().is_empty());
                assert_eq!(client_data.protocol(), b"h3");
                assert_eq!(server_data.protocol(), b"h3");
                assert_eq!(server_data.server_name(), Some(HOST));
                return Ok((*client_data, *server_data));
            }
            if round == 31 {
                return Err("handshake round bound exceeded".into());
            }
        }
        Err("handshake did not complete".into())
    }
}
