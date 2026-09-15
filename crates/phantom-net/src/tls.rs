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
    ssl::{SslConnector as BoringConnector, SslMethod, SslVerifyMode},
    x509::{X509, store::X509StoreBuilder},
};
use phantom_profile::{AlpsSettings, InvalidTlsSettings, NamedGroup, TlsSettings, TlsVersion};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as BoringStream;
use tracing::{Instrument, Span, debug, debug_span, field};

use self::configuration::extension_order_trace_name;
#[cfg(test)]
use self::configuration::require_supported;

mod compression;
mod configuration;

/// A reusable TLS connector with a validated immutable configuration.
#[derive(Clone)]
pub(crate) struct TlsConnector {
    backend: BoringConnector,
    alpn_wire: Box<[u8]>,
    alps: Option<AlpsSettings>,
    tls13_key_shares: Option<Box<[NamedGroup]>>,
    ech_grease: bool,
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
            .field("alpn_protocol_count", &count_alpn(&self.alpn_wire))
            .field("alps_protocol", &alps_protocol)
            .field("alps_settings_len", &alps_settings_len)
            .field("alps_use_new_codepoint", &alps_use_new_codepoint)
            .field("tls13_key_shares", &self.tls13_key_shares)
            .field("ech_grease", &self.ech_grease)
            .finish_non_exhaustive()
    }
}

impl TlsConnector {
    /// Builds a connector, rejecting invalid or unsupported settings immediately.
    pub(crate) fn new(settings: &TlsSettings) -> Result<Self, TlsError> {
        Self::build_with_roots(
            settings,
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(AsRef::as_ref),
        )
    }

    fn build_with_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, TlsError> {
        let span = debug_span!(
            "tls.connector.build",
            cipher_suite_count = settings.cipher_suites.len(),
            group_count = settings.groups.len(),
            signature_scheme_count = settings.signature_schemes.len(),
            alpn_protocol_count = settings.alpn_protocols.len(),
            certificate_compression_count = settings.certificate_compression.len(),
            session_tickets = settings.session_tickets,
            grease = settings.grease,
            extension_order = extension_order_trace_name(&settings.extension_order),
            ech_grease = settings.ech_grease,
            outcome = field::Empty,
            error_kind = field::Empty,
        );
        let _entered = span.enter();
        let result = Self::build_connector(settings, roots);
        record_tls_result(&span, &result);
        result
    }

    fn build_connector<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, TlsError> {
        settings
            .validate()
            .map_err(TlsError::invalid_configuration)?;

        debug!("building TLS connector");

        let mut root_store =
            X509StoreBuilder::new().map_err(|error| TlsError::backend("trust store", error))?;
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
        builder.set_verify(SslVerifyMode::PEER);
        configuration::apply(&mut builder, settings)?;

        if let Some(ids) = &settings.requested_trust_anchor_ids {
            builder
                .set_requested_trust_anchors(&encode_trust_anchor_ids(ids))
                .map_err(|error| TlsError::backend("requested_trust_anchor_ids", error))?;
        }

        let alpn_wire = encode_alpn(&settings.alpn_protocols)?;
        debug!("TLS connector built");

        Ok(Self {
            backend: builder.build(),
            alpn_wire,
            alps: settings.alps.clone(),
            tls13_key_shares: (settings.max_version == TlsVersion::Tls13)
                .then(|| settings.key_shares.clone().into_boxed_slice()),
            ech_grease: settings.ech_grease,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_with_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, TlsError> {
        Self::build_with_roots(settings, roots)
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
        let span = debug_span!(
            "tls.handshake",
            alpn_protocol_count = count_alpn(&self.alpn_wire),
            negotiated_alpn = field::Empty,
            alps_negotiated = field::Empty,
            peer_application_settings_len = field::Empty,
            tls_version = field::Empty,
            outcome = field::Empty,
            error_kind = field::Empty,
        );
        let outcome = HandshakeOutcome::new(&span);
        let result = async {
            debug!("TLS handshake started");

            let mut configuration = self
                .backend
                .configure()
                .map_err(|error| TlsError::backend("handshake configuration", error))?;
            configuration.set_use_server_name_indication(true);
            configuration.set_verify_hostname(true);
            configuration.set_enable_ech_grease(self.ech_grease);
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

            let ssl = configuration
                .into_ssl(server_name)
                .map_err(|error| TlsError::backend("server_name", error))?;
            let mut stream = BoringStream::new(ssl, stream)
                .map_err(|error| TlsError::backend("stream", error))?;
            Pin::new(&mut stream).connect().await.map_err(|error| {
                debug!("TLS handshake failed");
                TlsError::handshake(error)
            })?;

            let negotiated_alpn = stream.ssl().selected_alpn_protocol().map(Box::from);
            let peer_application_settings = stream.ssl().peer_application_settings().map(Box::from);
            span.record("negotiated_alpn", trace_alpn(negotiated_alpn.as_deref()));
            record_alps_negotiation(&span, peer_application_settings.as_deref());
            span.record("tls_version", stream.ssl().version_str());
            debug!(
                negotiated_alpn = trace_alpn(negotiated_alpn.as_deref()),
                alps_negotiated = peer_application_settings.is_some(),
                peer_application_settings_len =
                    peer_application_settings.as_deref().map_or(0, <[u8]>::len),
                tls_version = stream.ssl().version_str(),
                "TLS handshake completed"
            );
            Ok(TlsStream {
                inner: stream,
                negotiated_alpn,
                peer_application_settings,
            })
        }
        .instrument(span.clone())
        .await;
        outcome.finish(&result);
        result
    }
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
            self.span.record("outcome", "cancelled");
        }
    }
}

/// A connected TLS stream that hides its BoringSSL representation.
pub(crate) struct TlsStream<S> {
    inner: BoringStream<S>,
    negotiated_alpn: Option<Box<[u8]>>,
    peer_application_settings: Option<Box<[u8]>>,
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
            .finish_non_exhaustive()
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
#[non_exhaustive]
pub enum TlsErrorKind {
    /// Settings were internally inconsistent or incomplete.
    InvalidConfiguration,
    /// The configured TLS backend rejected a setting.
    BackendConfiguration,
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
            Self::UnsupportedSetting => "unsupported_setting",
            Self::Handshake => "handshake",
        }
    }
}

/// Error returned while constructing or using the TLS connector.
#[derive(Debug)]
pub struct TlsError {
    kind: TlsErrorKind,
    field: Option<&'static str>,
    message: Box<str>,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl TlsError {
    fn invalid_configuration(source: InvalidTlsSettings) -> Self {
        Self {
            kind: TlsErrorKind::InvalidConfiguration,
            field: None,
            message: source.to_string().into(),
            source: Some(Box::new(source)),
        }
    }

    fn configuration(field: &'static str, message: impl Into<Box<str>>) -> Self {
        Self {
            kind: TlsErrorKind::InvalidConfiguration,
            field: Some(field),
            message: message.into(),
            source: None,
        }
    }

    fn backend(field: &'static str, source: ErrorStack) -> Self {
        Self {
            kind: TlsErrorKind::BackendConfiguration,
            field: Some(field),
            message: "BoringSSL rejected the configured value".into(),
            source: Some(Box::new(source)),
        }
    }

    fn unsupported(field: &'static str, value: impl fmt::Debug) -> Self {
        Self {
            kind: TlsErrorKind::UnsupportedSetting,
            field: Some(field),
            message: format!("setting {value:?} is not supported by the BoringSSL adapter").into(),
            source: None,
        }
    }

    fn root_certificate(index: usize, source: ErrorStack) -> Self {
        Self {
            kind: TlsErrorKind::BackendConfiguration,
            field: Some("trust store"),
            message: format!("root certificate at index {index} is invalid").into(),
            source: Some(Box::new(source)),
        }
    }

    fn handshake(source: btls::ssl::Error) -> Self {
        Self {
            kind: TlsErrorKind::Handshake,
            field: None,
            message: "TLS handshake failed".into(),
            source: Some(Box::new(source)),
        }
    }

    /// Returns the broad failure category without exposing backend types.
    pub fn kind(&self) -> TlsErrorKind {
        self.kind
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
