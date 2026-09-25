//! BoringSSL-backed TLS connection setup.
//!
//! This module translates backend-neutral, ordered TLS settings into BoringSSL
//! configuration. The backend stays private so higher layers do not depend on
//! BoringSSL types.

use std::{
    error::Error as StdError,
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use btls::{
    error::ErrorStack,
    ssl::{
        SslConnector as BoringConnector, SslContext, SslContextBuilder, SslMethod, SslVerifyMode,
        SslVersion,
    },
    x509::{X509, store::X509StoreBuilder},
};
use phantom_profile::{
    AlpsSettings, CipherSuite, EchGreaseAead, InvalidTlsSettings, NamedGroup, TlsSettings,
    TlsVersion,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as BoringStream;
use tracing::{Instrument, Span, debug, debug_span, field};

use self::configuration::extension_order_trace_name;
#[cfg(test)]
use self::configuration::require_supported;
use self::session_cache::TlsSessionCache;

mod compression;
mod configuration;
#[cfg(feature = "keylog")]
pub(crate) mod key_log;
mod session_cache;

/// Policy for authenticating a TLS server certificate.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ServerAuthentication {
    /// Verify the certificate chain and the requested server name.
    #[default]
    WebPki,
    /// Accept the server certificate without chain or name verification.
    ///
    /// This is intended for controlled protocol conformance and diagnostics.
    /// Server Name Indication is still sent.
    Disabled,
}

impl ServerAuthentication {
    const fn trace_name(self) -> &'static str {
        match self {
            Self::WebPki => "webpki",
            Self::Disabled => "disabled",
        }
    }
}

/// A reusable TLS connector with a validated immutable configuration.
#[derive(Clone)]
pub(crate) struct TlsConnector {
    backend: BoringConnector,
    server_authentication: ServerAuthentication,
    alpn_wire: Box<[u8]>,
    alps: Option<AlpsSettings>,
    tls13_key_shares: Option<Box<[NamedGroup]>>,
    ech_grease: bool,
    ech_grease_payload_length: Option<u16>,
    ech_grease_aeads: Box<[EchGreaseAead]>,
    ech_from_https_records: bool,
    scoped_sessions_enabled: bool,
    session_cache: Option<TlsSessionCache>,
    #[cfg(feature = "keylog")]
    key_log: key_log::KeyLogSlot,
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alps_protocol = self
            .alps
            .as_ref()
            .map(|alps| trace_alpn(Some(&alps.protocol)));
        let alps_settings_len = self.alps.as_ref().map(|alps| alps.settings.len());
        let alps_use_new_codepoint = self.alps.as_ref().map(|alps| alps.use_new_codepoint);

        formatter
            .debug_struct("TlsConnector")
            .field("server_authentication", &self.server_authentication)
            .field("alpn_protocol_count", &count_alpn(&self.alpn_wire))
            .field("alps_protocol", &alps_protocol)
            .field("alps_settings_len", &alps_settings_len)
            .field("alps_use_new_codepoint", &alps_use_new_codepoint)
            .field("tls13_key_shares", &self.tls13_key_shares)
            .field("ech_grease", &self.ech_grease)
            .field("ech_grease_payload_length", &self.ech_grease_payload_length)
            .field("ech_grease_aeads", &self.ech_grease_aeads)
            .finish_non_exhaustive()
    }
}

impl TlsConnector {
    /// Builds a connector, rejecting invalid or unsupported settings immediately.
    pub(crate) fn new(settings: &TlsSettings) -> Result<Self, TlsError> {
        Self::build_with_roots(
            settings,
            ServerAuthentication::WebPki,
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(AsRef::as_ref),
        )
    }

    /// Builds a connector with the bundled public roots and additional DER certificates.
    pub(crate) fn new_with_additional_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, TlsError> {
        Self::build_with_roots(
            settings,
            ServerAuthentication::WebPki,
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(AsRef::as_ref)
                .chain(roots),
        )
    }

    /// Builds a connector with an explicit server-authentication policy.
    pub(crate) fn new_with_server_authentication(
        settings: &TlsSettings,
        server_authentication: ServerAuthentication,
    ) -> Result<Self, TlsError> {
        match server_authentication {
            ServerAuthentication::WebPki => Self::new(settings),
            ServerAuthentication::Disabled => Self::build_with_roots(
                settings,
                ServerAuthentication::Disabled,
                std::iter::empty::<&[u8]>(),
            ),
        }
    }

    /// Builds a connector for QUIC with the bundled public roots and `roots`.
    ///
    /// The TCP scoped-session machinery is never installed. When the profile
    /// enables session tickets, `prepare_sessions` receives the builder so the
    /// QUIC adapter can install its own ticket delivery. The key-log callback
    /// is installed as for TCP connectors.
    pub(crate) fn new_quic_with_additional_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
        mut prepare_sessions: impl FnMut(&mut SslContextBuilder),
    ) -> Result<Self, TlsError> {
        if settings.ech_from_https_records {
            return Err(TlsError::unsupported("ech_from_https_records", true));
        }
        Self::build_with_roots_and_sessions(
            settings,
            ServerAuthentication::WebPki,
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(AsRef::as_ref)
                .chain(roots),
            ClientSessions::External(&mut prepare_sessions),
        )
    }

    /// Consumes this connector and returns its configured TLS context.
    pub(crate) fn into_context(self) -> SslContext {
        self.backend.into_context()
    }

    /// Returns the key-log slot of this connector's TLS context.
    #[cfg(feature = "keylog")]
    pub(crate) fn key_log(&self) -> &key_log::KeyLogSlot {
        &self.key_log
    }

    pub(crate) fn with_isolated_session_cache(&self) -> Self {
        let mut connector = self.clone();
        connector.session_cache = self.scoped_sessions_enabled.then(TlsSessionCache::default);
        connector
    }

    /// Returns whether the profile uses an HTTPS record's `ech` on direct
    /// TCP connections; see `TlsSettings::ech_from_https_records`.
    pub(crate) const fn ech_from_https_records(&self) -> bool {
        self.ech_from_https_records
    }

    /// Returns the offered ALPN protocols in preference order.
    pub(crate) fn alpn_protocols(&self) -> Vec<Box<[u8]>> {
        let mut protocols = Vec::new();
        let mut remaining = self.alpn_wire.as_ref();
        while let Some((&length, rest)) = remaining.split_first() {
            let Some((protocol, tail)) = rest.split_at_checked(usize::from(length)) else {
                break;
            };
            protocols.push(Box::from(protocol));
            remaining = tail;
        }
        protocols
    }

    pub(crate) fn offers_alpn(&self, expected: &[u8]) -> bool {
        let mut remaining = self.alpn_wire.as_ref();

        while let Some((&length, protocols)) = remaining.split_first() {
            let length = usize::from(length);
            let Some((protocol, tail)) = protocols.split_at_checked(length) else {
                return false;
            };
            if protocol == expected {
                return true;
            }
            remaining = tail;
        }

        false
    }

    fn build_with_roots<'a>(
        settings: &TlsSettings,
        server_authentication: ServerAuthentication,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, TlsError> {
        Self::build_with_roots_and_sessions(
            settings,
            server_authentication,
            roots,
            ClientSessions::Scoped,
        )
    }

    fn build_with_roots_and_sessions<'a>(
        settings: &TlsSettings,
        server_authentication: ServerAuthentication,
        roots: impl IntoIterator<Item = &'a [u8]>,
        sessions: ClientSessions<'_>,
    ) -> Result<Self, TlsError> {
        let span = debug_span!(
            "tls.connector.build",
            cipher_suite_count = settings.cipher_suites.len(),
            group_count = settings.groups.len(),
            signature_scheme_count = settings.signature_schemes.len(),
            delegated_credential_signature_scheme_count =
                settings.delegated_credential_schemes.len(),
            alpn_protocol_count = settings.alpn_protocols.len(),
            certificate_compression_count = settings.certificate_compression.len(),
            session_tickets = settings.session_tickets,
            record_size_limit_configured = settings.record_size_limit.is_some(),
            grease = settings.grease,
            extension_order = extension_order_trace_name(&settings.extension_order),
            ech_grease = settings.ech_grease,
            ech_grease_payload_length_configured = settings.ech_grease_payload_length.is_some(),
            ech_grease_aead_count = settings.ech_grease_aeads.len(),
            server_authentication = server_authentication.trace_name(),
            outcome = field::Empty,
            error_kind = field::Empty,
        );
        let _entered = span.enter();
        let result = Self::build_connector(settings, server_authentication, roots, sessions);
        record_tls_result(&span, &result);
        result
    }

    fn build_connector<'a>(
        settings: &TlsSettings,
        server_authentication: ServerAuthentication,
        roots: impl IntoIterator<Item = &'a [u8]>,
        sessions: ClientSessions<'_>,
    ) -> Result<Self, TlsError> {
        settings
            .validate()
            .map_err(TlsError::invalid_configuration)?;

        debug!("building TLS connector");

        let mut root_store = X509StoreBuilder::new()
            .map_err(|error| TlsError::trust_store("failed to create trust store", error))?;
        for (index, der) in roots.into_iter().enumerate() {
            let certificate =
                X509::from_der(der).map_err(|error| TlsError::root_certificate(index, error))?;
            root_store
                .add_cert(certificate)
                .map_err(|error| TlsError::root_certificate(index, error))?;
        }

        let mut builder = BoringConnector::bare_builder(SslMethod::tls())
            .map_err(|error| TlsError::backend("connector", error))?;
        builder.set_cert_store_builder(root_store);
        builder.set_verify(match server_authentication {
            ServerAuthentication::WebPki => SslVerifyMode::PEER,
            ServerAuthentication::Disabled => SslVerifyMode::NONE,
        });
        configuration::apply(&mut builder, settings)?;

        if let Some(ids) = &settings.requested_trust_anchor_ids {
            builder
                .set_requested_trust_anchors(&encode_trust_anchor_ids(ids))
                .map_err(|error| TlsError::backend("requested_trust_anchor_ids", error))?;
        }

        let tickets_verifiable = settings.session_tickets
            && matches!(server_authentication, ServerAuthentication::WebPki);
        let scoped_sessions_enabled = match sessions {
            ClientSessions::Scoped if tickets_verifiable => {
                builder.enable_scoped_client_sessions();
                true
            }
            ClientSessions::External(prepare) if tickets_verifiable => {
                prepare(&mut builder);
                false
            }
            ClientSessions::Scoped | ClientSessions::External(_) => false,
        };

        #[cfg(feature = "keylog")]
        let key_log = key_log::KeyLogSlot::default();
        #[cfg(feature = "keylog")]
        key_log.install(&mut builder);

        let alpn_wire = encode_alpn(&settings.alpn_protocols)?;
        debug!("TLS connector built");

        Ok(Self {
            backend: builder.build(),
            server_authentication,
            alpn_wire,
            alps: settings.alps.clone(),
            tls13_key_shares: (settings.max_version == TlsVersion::Tls13)
                .then(|| settings.key_shares.clone().into_boxed_slice()),
            ech_grease: settings.ech_grease,
            ech_grease_payload_length: settings.ech_grease_payload_length,
            ech_grease_aeads: settings.ech_grease_aeads.clone().into_boxed_slice(),
            ech_from_https_records: settings.ech_from_https_records,
            scoped_sessions_enabled,
            session_cache: None,
            #[cfg(feature = "keylog")]
            key_log,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_with_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, TlsError> {
        Self::build_with_roots(settings, ServerAuthentication::WebPki, roots)
    }

    /// Performs a TLS client handshake over an already-connected byte stream.
    pub(crate) async fn connect<S>(
        &self,
        server_name: &str,
        stream: S,
    ) -> Result<TlsStream<S>, TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_with_ech(server_name, stream, None).await
    }

    /// Performs a TLS client handshake that offers `ech_config_list`, the
    /// bytes of an `ECHConfigList`, as Chromium's `ConfigureEch` does.
    ///
    /// ECH GREASE stays as the profile sets it; BoringSSL replaces it with
    /// real ECH when the list holds a configuration it supports. A list
    /// BoringSSL rejects fails with [`EchFailure::InvalidConfigList`] before
    /// any TLS byte is written. A server that cannot decrypt the inner
    /// ClientHello and authenticates as the public name fails the handshake
    /// with [`EchFailure::Rejected`], carrying its retry configurations.
    pub(crate) async fn connect_with_ech<S>(
        &self,
        server_name: &str,
        stream: S,
        ech_config_list: Option<&[u8]>,
    ) -> Result<TlsStream<S>, TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let span = debug_span!(
            "tls.handshake",
            ech_offered = ech_config_list.is_some(),
            ech_accepted = field::Empty,
            alpn_protocol_count = count_alpn(&self.alpn_wire),
            negotiated_alpn = field::Empty,
            alps_negotiated = field::Empty,
            peer_application_settings_len = field::Empty,
            tls_version = field::Empty,
            cipher_suite = field::Empty,
            session_reused = field::Empty,
            server_authentication = self.server_authentication.trace_name(),
            outcome = field::Empty,
            error_kind = field::Empty,
        );
        let outcome = HandshakeOutcome::new(&span);
        let result = async {
            debug!("TLS handshake started");
            let mut attempted_reusable_session = None;
            let mut session_capture = None;

            let mut configuration = self
                .backend
                .configure()
                .map_err(|error| TlsError::backend("handshake configuration", error))?;
            configuration.set_use_server_name_indication(true);
            configuration.set_verify_hostname(matches!(
                self.server_authentication,
                ServerAuthentication::WebPki
            ));
            configuration.set_enable_ech_grease(self.ech_grease);
            if let Some(payload_length) = self.ech_grease_payload_length {
                configuration
                    .set_ech_grease_payload_length(usize::from(payload_length))
                    .map_err(|error| TlsError::backend("ech_grease_payload_length", error))?;
            }
            if !self.ech_grease_aeads.is_empty() {
                let aead_ids = self
                    .ech_grease_aeads
                    .iter()
                    .map(|aead| aead.hpke_id())
                    .collect::<Vec<_>>();
                configuration
                    .set_ech_grease_aeads(&aead_ids)
                    .map_err(|error| TlsError::backend("ech_grease_aeads", error))?;
            }
            if let Some(list) = ech_config_list {
                configuration
                    .set_ech_config_list(list)
                    .map_err(TlsError::invalid_ech_config_list)?;
            }
            configuration
                .set_alpn_protos(&self.alpn_wire)
                .map_err(|error| TlsError::backend("alpn_protocols", error))?;

            if let Some(alps) = &self.alps {
                configuration
                    .add_application_settings_with_payload(&alps.protocol, &alps.settings)
                    .map_err(|error| TlsError::backend("alps", error))?;
                configuration.set_alps_use_new_codepoint(alps.use_new_codepoint);
            }

            if let Some(key_shares) = &self.tls13_key_shares {
                let key_shares = key_shares
                    .iter()
                    .copied()
                    .map(configuration::key_share)
                    .collect::<Result<Vec<_>, _>>()?;
                configuration
                    .set_client_key_shares(&key_shares)
                    .map_err(|error| TlsError::backend("key_shares", error))?;
            }

            let ssl = if let Some(cache) = &self.session_cache {
                let session = cache.take(server_name);
                let reusable = session
                    .as_ref()
                    .is_some_and(|session| !session.should_be_single_use());
                let capture = cache.begin_handshake(server_name);
                let callback_capture = capture.clone();
                let ssl = configuration
                    .into_ssl_with_scoped_session(
                        server_name,
                        cache.scope(),
                        session.as_ref(),
                        move |session| callback_capture.capture(session),
                    )
                    .map_err(|error| TlsError::backend("session resumption", error))?
                    .ok_or_else(|| {
                        TlsError::configuration(
                            "session resumption",
                            "cached session does not match its connector scope and hostname",
                        )
                    })?;
                if reusable {
                    attempted_reusable_session = session;
                }
                session_capture = Some(capture);
                ssl
            } else {
                configuration
                    .into_ssl(server_name)
                    .map_err(|error| TlsError::backend("server_name", error))?
            };
            let mut stream = BoringStream::new(ssl, stream)
                .map_err(|error| TlsError::backend("stream", error))?;
            if let Err(error) = Pin::new(&mut stream).connect().await {
                debug!("TLS handshake failed");
                if is_ech_rejection(&error) {
                    // BoringSSL releases retry configurations only after
                    // SSL_R_ECH_REJECTED, which authenticates them.
                    let retry_configs = stream
                        .ssl()
                        .get_ech_retry_configs()
                        .filter(|configs| !configs.is_empty())
                        .map(Box::from);
                    return Err(TlsError::ech_rejected(error, retry_configs));
                }
                return Err(TlsError::handshake(error));
            }
            let ech_accepted = stream.ssl().ech_accepted();
            span.record("ech_accepted", ech_accepted);

            let negotiated_alpn = stream.ssl().selected_alpn_protocol().map(Box::from);
            let peer_application_settings = stream.ssl().peer_application_settings().map(Box::from);
            let negotiated_tls_version = negotiated_tls_version(stream.ssl().version2());
            let negotiated_cipher = stream.ssl().current_cipher();
            let negotiated_cipher_suite = negotiated_cipher
                .and_then(|cipher| CipherSuite::from_iana_id(cipher.protocol_id()));
            let negotiated_cipher_name = negotiated_cipher
                .and_then(|cipher| cipher.standard_name())
                .unwrap_or("unknown");
            let session_reused = stream.ssl().session_reused();
            let captured_session_count = session_capture
                .as_ref()
                .map_or(0, session_cache::TlsSessionCapture::commit_authenticated);
            if session_reused
                && captured_session_count == 0
                && let (Some(cache), Some(session)) =
                    (&self.session_cache, attempted_reusable_session)
            {
                cache.restore(server_name, session);
            }
            span.record("negotiated_alpn", trace_alpn(negotiated_alpn.as_deref()));
            record_alps_negotiation(&span, peer_application_settings.as_deref());
            span.record("tls_version", stream.ssl().version_str());
            span.record("cipher_suite", negotiated_cipher_name);
            span.record("session_reused", session_reused);
            debug!(
                negotiated_alpn = trace_alpn(negotiated_alpn.as_deref()),
                alps_negotiated = peer_application_settings.is_some(),
                peer_application_settings_len =
                    peer_application_settings.as_deref().map_or(0, <[u8]>::len),
                tls_version = stream.ssl().version_str(),
                cipher_suite = negotiated_cipher_name,
                session_reused,
                "TLS handshake completed"
            );
            Ok(TlsStream {
                inner: stream,
                ech_accepted,
                negotiated_alpn,
                peer_application_settings,
                negotiated_tls_version,
                negotiated_cipher_suite,
                session_reused,
            })
        }
        .instrument(span.clone())
        .await;
        outcome.finish(&result);
        result
    }
}

/// Which component owns client-session handling for a new context.
enum ClientSessions<'p> {
    /// TCP connections use scoped sessions; see
    /// [`TlsConnector::with_isolated_session_cache`].
    Scoped,
    /// Another adapter, such as QUIC, installs its own session handling.
    External(&'p mut dyn FnMut(&mut SslContextBuilder)),
}

fn record_tls_result<T>(span: &Span, result: &Result<T, TlsError>) {
    match result {
        Ok(_) => {
            span.record("outcome", "ok");
        }
        Err(error) => {
            span.record("outcome", "error");
            span.record("error_kind", error.kind().trace_name());
        }
    }
}

struct HandshakeOutcome {
    span: Span,
    recorded: bool,
}

impl HandshakeOutcome {
    fn new(span: &Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish<T>(mut self, result: &Result<T, TlsError>) {
        record_tls_result(&self.span, result);
        self.recorded = true;
    }
}

impl Drop for HandshakeOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            let outcome = if std::thread::panicking() {
                "panicked"
            } else {
                "cancelled"
            };
            self.span.record("outcome", outcome);
        }
    }
}

/// A connected TLS stream that hides its BoringSSL representation.
pub(crate) struct TlsStream<S> {
    inner: BoringStream<S>,
    ech_accepted: bool,
    negotiated_alpn: Option<Box<[u8]>>,
    peer_application_settings: Option<Box<[u8]>>,
    negotiated_tls_version: Option<TlsVersion>,
    negotiated_cipher_suite: Option<CipherSuite>,
    session_reused: bool,
}

impl<S> TlsStream<S> {
    /// Returns the ALPN protocol selected by the server, if any.
    pub(crate) fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Returns the peer's ALPS value, preserving negotiated-empty settings.
    pub(crate) fn peer_application_settings(&self) -> Option<&[u8]> {
        self.peer_application_settings.as_deref()
    }

    /// Returns the negotiated TLS protocol version.
    pub(crate) fn negotiated_tls_version(&self) -> Option<TlsVersion> {
        self.negotiated_tls_version
    }

    /// Returns the negotiated TLS cipher suite.
    pub(crate) fn negotiated_cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_cipher_suite
    }

    /// Returns whether the handshake resumed a cached TLS session.
    pub(crate) const fn session_reused(&self) -> bool {
        self.session_reused
    }
}

impl<S> fmt::Debug for TlsStream<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsStream")
            .field(
                "negotiated_alpn",
                &self
                    .negotiated_alpn
                    .as_deref()
                    .and_then(recognized_alpn_name),
            )
            .field(
                "alps_negotiated",
                &self.peer_application_settings().is_some(),
            )
            .field(
                "peer_application_settings_len",
                &self.peer_application_settings().map_or(0, <[u8]>::len),
            )
            .field("negotiated_tls_version", &self.negotiated_tls_version())
            .field("negotiated_cipher_suite", &self.negotiated_cipher_suite())
            .field("session_reused", &self.session_reused())
            .field("ech_accepted", &self.ech_accepted)
            .finish_non_exhaustive()
    }
}

fn negotiated_tls_version(version: Option<SslVersion>) -> Option<TlsVersion> {
    match version? {
        SslVersion::TLS1 => Some(TlsVersion::Tls10),
        SslVersion::TLS1_1 => Some(TlsVersion::Tls11),
        SslVersion::TLS1_2 => Some(TlsVersion::Tls12),
        SslVersion::TLS1_3 => Some(TlsVersion::Tls13),
        _ => None,
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Category of a TLS connection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsErrorKind {
    /// Settings were internally inconsistent or incomplete.
    InvalidConfiguration,
    /// The configured TLS backend rejected a setting.
    BackendConfiguration,
    /// A configured trust root could not be loaded.
    TrustStore,
    /// The profile contains a setting this backend version cannot translate.
    UnsupportedSetting,
    /// The TLS handshake failed.
    Handshake,
}

impl TlsErrorKind {
    fn trace_name(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid_configuration",
            Self::BackendConfiguration => "backend_configuration",
            Self::TrustStore => "trust_store",
            Self::UnsupportedSetting => "unsupported_setting",
            Self::Handshake => "handshake",
        }
    }
}

/// Why a connection that offered Encrypted Client Hello failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EchFailure {
    /// BoringSSL rejected the `ECHConfigList` before the handshake, as
    /// Chrome's `ERR_INVALID_ECH_CONFIG_LIST`.
    InvalidConfigList,
    /// The server could not decrypt the inner ClientHello and completed the
    /// handshake as the configuration's public name, as Chrome's
    /// `ERR_ECH_NOT_NEGOTIATED`.
    Rejected,
}

/// `ERR_LIB_SSL`, the sixteenth library code in BoringSSL's
/// `include/openssl/err.h`.
const ERR_LIB_SSL: i32 = 16;
/// `SSL_R_ECH_REJECTED` in BoringSSL's `include/openssl/ssl.h`.
const SSL_R_ECH_REJECTED: i32 = 319;

fn is_ech_rejection(error: &btls::ssl::Error) -> bool {
    error.ssl_error().is_some_and(|stack| {
        stack.errors().iter().any(|entry| {
            entry.library_code() == ERR_LIB_SSL && entry.reason_code() == SSL_R_ECH_REJECTED
        })
    })
}

/// Error returned while constructing or using the TLS connector.
#[derive(Debug)]
pub struct TlsError {
    kind: TlsErrorKind,
    field: Option<&'static str>,
    message: Box<str>,
    source: Option<Box<dyn StdError + Send + Sync>>,
    ech: Option<EchFailure>,
    ech_retry_configs: Option<Box<[u8]>>,
}

impl TlsError {
    fn new(
        kind: TlsErrorKind,
        field: Option<&'static str>,
        message: Box<str>,
        source: Option<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self {
            kind,
            field,
            message,
            source,
            ech: None,
            ech_retry_configs: None,
        }
    }

    fn invalid_configuration(source: InvalidTlsSettings) -> Self {
        Self::new(
            TlsErrorKind::InvalidConfiguration,
            None,
            source.to_string().into(),
            Some(Box::new(source)),
        )
    }

    fn configuration(field: &'static str, message: impl Into<Box<str>>) -> Self {
        Self::new(
            TlsErrorKind::InvalidConfiguration,
            Some(field),
            message.into(),
            None,
        )
    }

    fn backend(field: &'static str, source: ErrorStack) -> Self {
        Self::new(
            TlsErrorKind::BackendConfiguration,
            Some(field),
            "BoringSSL rejected the configured value".into(),
            Some(Box::new(source)),
        )
    }

    pub(crate) fn invalid_ech_config_list(source: impl StdError + Send + Sync + 'static) -> Self {
        let mut error = Self::new(
            TlsErrorKind::InvalidConfiguration,
            Some("ech_config_list"),
            "the ECHConfigList does not parse".into(),
            Some(Box::new(source)),
        );
        error.ech = Some(EchFailure::InvalidConfigList);
        error
    }

    fn ech_rejected(source: btls::ssl::Error, retry_configs: Option<Box<[u8]>>) -> Self {
        let mut error = Self::new(
            TlsErrorKind::Handshake,
            None,
            "server rejected Encrypted Client Hello".into(),
            Some(Box::new(source)),
        );
        error.ech = Some(EchFailure::Rejected);
        error.ech_retry_configs = retry_configs;
        error
    }

    fn unsupported(field: &'static str, value: impl fmt::Debug) -> Self {
        Self::new(
            TlsErrorKind::UnsupportedSetting,
            Some(field),
            format!("setting {value:?} is not supported by the BoringSSL adapter").into(),
            None,
        )
    }

    fn root_certificate(index: usize, source: ErrorStack) -> Self {
        Self::trust_store(
            format!("root certificate at index {index} is invalid"),
            source,
        )
    }

    fn trust_store(message: impl Into<Box<str>>, source: ErrorStack) -> Self {
        Self::new(
            TlsErrorKind::TrustStore,
            Some("trust store"),
            message.into(),
            Some(Box::new(source)),
        )
    }

    fn handshake(source: btls::ssl::Error) -> Self {
        Self::new(
            TlsErrorKind::Handshake,
            None,
            "TLS handshake failed".into(),
            Some(Box::new(source)),
        )
    }

    /// Returns the broad failure category without exposing backend types.
    pub fn kind(&self) -> TlsErrorKind {
        self.kind
    }

    /// Returns why a connection that offered Encrypted Client Hello failed,
    /// when that is the cause.
    #[must_use]
    pub const fn ech_failure(&self) -> Option<EchFailure> {
        self.ech
    }

    /// Takes the retry configurations an ECH rejection carried; `None` when
    /// the server sent none, which asks for a retry without ECH.
    #[cfg_attr(not(feature = "https-records"), allow(dead_code))]
    pub(crate) fn take_ech_retry_configs(&mut self) -> Option<Box<[u8]>> {
        self.ech_retry_configs.take()
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(field) = self.field {
            write!(formatter, "invalid TLS {field}: {}", self.message)
        } else {
            formatter.write_str(&self.message)
        }
    }
}

impl StdError for TlsError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

fn encode_alpn(protocols: &[Box<[u8]>]) -> Result<Box<[u8]>, TlsError> {
    if protocols.is_empty() {
        return Err(TlsError::configuration(
            "alpn_protocols",
            "at least one ALPN protocol is required",
        ));
    }

    let capacity = protocols.iter().try_fold(0usize, |length, protocol| {
        if protocol.is_empty() || protocol.len() > u8::MAX as usize {
            return Err(TlsError::configuration(
                "alpn_protocols",
                "each ALPN protocol must contain 1..=255 bytes",
            ));
        }
        length
            .checked_add(1 + protocol.len())
            .ok_or_else(|| TlsError::configuration("alpn_protocols", "encoded list is too large"))
    })?;
    if capacity > u16::MAX as usize {
        return Err(TlsError::configuration(
            "alpn_protocols",
            "encoded ALPN protocol list exceeds 65535 bytes",
        ));
    }

    let mut encoded = Vec::with_capacity(capacity);
    for protocol in protocols {
        encoded.push(protocol.len() as u8);
        encoded.extend_from_slice(protocol);
    }
    Ok(encoded.into_boxed_slice())
}

fn encode_trust_anchor_ids(ids: &[Box<[u8]>]) -> Box<[u8]> {
    let capacity = ids.iter().map(|id| 1 + id.len()).sum();
    let mut encoded = Vec::with_capacity(capacity);
    for id in ids {
        encoded.push(id.len() as u8);
        encoded.extend_from_slice(id);
    }
    encoded.into_boxed_slice()
}

fn count_alpn(mut encoded: &[u8]) -> usize {
    let mut count = 0;
    while let Some((&length, rest)) = encoded.split_first() {
        count += 1;
        encoded = &rest[usize::from(length)..];
    }
    count
}

fn recognized_alpn_name(protocol: &[u8]) -> Option<&'static str> {
    match protocol {
        b"http/1.1" => Some("http/1.1"),
        b"h2" => Some("h2"),
        b"h3" => Some("h3"),
        _ => None,
    }
}

pub(crate) fn trace_alpn(protocol: Option<&[u8]>) -> &'static str {
    match protocol {
        None => "none",
        Some(b"http/1.1") => "http/1.1",
        Some(b"h2") => "h2",
        Some(b"h3") => "h3",
        Some(_) => "other",
    }
}

fn record_alps_negotiation(span: &Span, peer_application_settings: Option<&[u8]>) {
    span.record("alps_negotiated", peer_application_settings.is_some());
    span.record(
        "peer_application_settings_len",
        peer_application_settings.map_or(0, <[u8]>::len),
    );
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
