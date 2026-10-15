//! Real authenticated tickets and all-or-nothing TCP store replacement.

use super::super::super::*;
use crate::session_tickets::tcp_transfer::TcpSessionStoreHeader;
use crate::tls::test_support::{TEST_SERVER_NAME as NAME, TEST_TIMEOUT, TestIdentity, TestResult};
use btls::ssl::{
    SessionImportPermit, Ssl, SslAcceptor, SslConnector, SslMethod, SslVersion, open_envelope,
    seal_envelope,
};
use btls::x509::X509;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_btls::SslStream;

fn policy() -> Result<SessionTransferPolicy, SessionTransferError> {
    SessionTransferPolicy::new(b"synthetic TCP storage policy", &[0, 0], None, &[3; 32])
}

pub(super) struct Fixture {
    pub(super) cache: TlsSessionCache,
    pub(super) client: SslConnector,
    server: SslAcceptor,
    pub(super) binding: SessionPolicyBinding,
}
impl Fixture {
    pub(super) fn new(order: TicketOrder, limit: u8, version: SslVersion) -> TestResult<Self> {
        let identity = TestIdentity::generate()?;
        let mut client = SslConnector::builder(SslMethod::tls())?;
        client
            .cert_store_mut()
            .add_cert(X509::from_der(identity.root_der())?)?;
        client.set_min_proto_version(Some(version))?;
        client.set_max_proto_version(Some(version))?;
        client.enable_scoped_client_sessions();
        let client = client.build();
        let cache = TlsSessionCache::new(limit, order, client.context().to_owned());
        let binding = cache
            .control()
            .upgrade()
            .ok_or("cache owner missing")?
            .bind_transfer_policy(NAME, policy()?)?;
        let mut server = identity.acceptor_builder()?;
        server.set_min_proto_version(Some(version))?;
        server.set_max_proto_version(Some(version))?;
        Ok(Self {
            cache,
            client,
            server: server.build(),
            binding,
        })
    }

    pub(super) async fn seed(&self, connections: usize) -> TestResult<()> {
        for _ in 0..connections {
            let capture = self.cache.begin_handshake(NAME);
            let callback = capture.clone();
            let mut configuration = self.client.configure()?;
            configuration.set_session_transfer_policy(&self.binding)?;
            let ssl = configuration
                .into_ssl_with_session_transfer(NAME, self.cache.scope(), None, move |session| {
                    callback.capture(session)
                })?
                .ok_or("TLS finalization declined")?;
            let (left, right) = tokio::io::duplex(64 * 1024);
            let mut client = SslStream::new(ssl, left)?;
            let mut server = SslStream::new(Ssl::new(self.server.context())?, right)?;
            // Both futures remain owned here, including failure/timeout/panic.
            tokio::time::timeout(TEST_TIMEOUT, async {
                tokio::try_join!(
                    async {
                        Pin::new(&mut client).connect().await?;
                        let mut reply = [0];
                        client.read_exact(&mut reply).await?;
                        assert_eq!(reply, [b'x']);
                        assert!(client.ssl().authenticate_scoped_session_publication());
                        capture.commit_authenticated();
                        assert!(!client.ssl().session_reused());
                        client.write_all(b"a").await?;
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                    },
                    async {
                        Pin::new(&mut server).accept().await?;
                        server.write_all(b"x").await?;
                        server.flush().await?;
                        let mut reply = [0];
                        server.read_exact(&mut reply).await?;
                        assert_eq!(reply, [b'a']);
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                    }
                )
            })
            .await??;
        }
        assert!(self.cache.len() != 0);
        Ok(())
    }

    pub(super) fn authorized(
        &self,
        recipient: &Fixture,
    ) -> TestResult<(TcpSessionStoreHeader, Vec<SessionImportPermit>)> {
        let owner = self
            .cache
            .control()
            .upgrade()
            .ok_or("source owner missing")?;
        let mut exports = TlsSessionOwner::capture_stores(&[(&owner, NAME)])?;
        let export = exports.pop().ok_or("export missing")?;
        let header = export.header();
        let mut records = Vec::new();
        for record in export.into_records() {
            records.push(record.seal(b"synthetic facade payload", &[9; 32])?);
        }
        let envelope = seal_envelope(&records, &[9; 32])?;
        let mut verified =
            open_envelope(envelope.as_bytes(), &[9; 32], recipient.client.context())?;
        let mut permits: Vec<SessionImportPermit> = Vec::new();
        for index in 0..header.record_count() {
            // This synthetic fixed policy permits exactly the absent two-leg draw.
            // Production facade must check its original typed policies instead.
            assert_eq!(verified.source_witness(index)?, &[0, 0]);
            permits.push(verified.authorize_record(index, &recipient.binding)?);
        }
        Ok((header, permits))
    }
    pub(super) fn prepare(
        &self,
        recipient: &Fixture,
    ) -> TestResult<transfer::PreparedTlsSessionReplacement> {
        let (header, permits) = self.authorized(recipient)?;
        Ok(recipient
            .cache
            .control()
            .upgrade()
            .ok_or("recipient owner missing")?
            .prepare_replacement(NAME.into(), header, permits)?)
    }
}

pub(super) fn arrivals(cache: &TlsSessionCache) -> (Vec<Arrival>, u64, Arc<()>) {
    let store = cache.store();
    (
        store.sessions.iter().map(|cached| cached.arrival).collect(),
        store.next_batch,
        Arc::clone(&store.generation),
    )
}
