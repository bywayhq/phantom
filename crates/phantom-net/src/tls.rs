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
        CertificateCompressionAlgorithm as BoringCertificateCompressionAlgorithm,
        CertificateCompressor, KeyShare, SslConnector as BoringConnector, SslMethod, SslOptions,
        SslVerifyMode, SslVersion,
    },
    x509::{X509, store::X509StoreBuilder},
};
use phantom_profile::{
    AlpsSettings, CertificateCompression, CipherSuite, InvalidTlsSettings, NamedGroup,
    SignatureScheme, TlsSettings, TlsVersion,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as BoringStream;
use tracing::{Instrument, Span, debug, debug_span, field};

fn boring_version(field: &'static str, version: TlsVersion) -> Result<SslVersion, TlsError> {
    let mapped = match version {
        TlsVersion::Tls12 => Some(SslVersion::TLS1_2),
        TlsVersion::Tls13 => Some(SslVersion::TLS1_3),
        _ => None,
    };
    require_supported(field, version, mapped)
}

fn cipher_name(cipher: CipherSuite) -> Result<&'static str, TlsError> {
    let mapped = match cipher {
        CipherSuite::Aes128GcmSha256 => Some("TLS_AES_128_GCM_SHA256"),
        CipherSuite::Aes256GcmSha384 => Some("TLS_AES_256_GCM_SHA384"),
        CipherSuite::Chacha20Poly1305Sha256 => Some("TLS_CHACHA20_POLY1305_SHA256"),
        CipherSuite::EcdheEcdsaAes128GcmSha256 => Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        CipherSuite::EcdheRsaAes128GcmSha256 => Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        CipherSuite::EcdheEcdsaAes256GcmSha384 => Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        CipherSuite::EcdheRsaAes256GcmSha384 => Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        CipherSuite::EcdheEcdsaChacha20Poly1305Sha256 => {
            Some("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
        }
        CipherSuite::EcdheRsaChacha20Poly1305Sha256 => {
            Some("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
        }
        CipherSuite::EcdheRsaAes128CbcSha => Some("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
        CipherSuite::EcdheRsaAes256CbcSha => Some("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
        CipherSuite::RsaAes128GcmSha256 => Some("TLS_RSA_WITH_AES_128_GCM_SHA256"),
        CipherSuite::RsaAes256GcmSha384 => Some("TLS_RSA_WITH_AES_256_GCM_SHA384"),
        CipherSuite::RsaAes128CbcSha => Some("TLS_RSA_WITH_AES_128_CBC_SHA"),
        CipherSuite::RsaAes256CbcSha => Some("TLS_RSA_WITH_AES_256_CBC_SHA"),
        _ => None,
    };
    require_supported("cipher_suites", cipher, mapped)
}

fn group_name(group: NamedGroup) -> Result<&'static str, TlsError> {
    let mapped = match group {
        NamedGroup::X25519MlKem768 => Some("X25519MLKEM768"),
        NamedGroup::X25519 => Some("X25519"),
        NamedGroup::Secp256r1 => Some("P-256"),
        NamedGroup::Secp384r1 => Some("P-384"),
        _ => None,
    };
    require_supported("groups", group, mapped)
}

fn boring_key_share(group: NamedGroup) -> Result<KeyShare, TlsError> {
    let mapped = match group {
        NamedGroup::X25519MlKem768 => Some(KeyShare::X25519_MLKEM768),
        NamedGroup::X25519 => Some(KeyShare::X25519),
        NamedGroup::Secp256r1 => Some(KeyShare::P256),
        NamedGroup::Secp384r1 => Some(KeyShare::P384),
        _ => None,
    };
    require_supported("key_shares", group, mapped)
}

fn signature_name(scheme: SignatureScheme) -> Result<&'static str, TlsError> {
    let mapped = match scheme {
        SignatureScheme::MlDsa44 => Some("mldsa44"),
        SignatureScheme::MlDsa65 => Some("mldsa65"),
        SignatureScheme::MlDsa87 => Some("mldsa87"),
        SignatureScheme::EcdsaSecp256r1Sha256 => Some("ecdsa_secp256r1_sha256"),
        SignatureScheme::RsaPssRsaeSha256 => Some("rsa_pss_rsae_sha256"),
        SignatureScheme::RsaPkcs1Sha256 => Some("rsa_pkcs1_sha256"),
        SignatureScheme::EcdsaSecp384r1Sha384 => Some("ecdsa_secp384r1_sha384"),
        SignatureScheme::RsaPssRsaeSha384 => Some("rsa_pss_rsae_sha384"),
        SignatureScheme::RsaPkcs1Sha384 => Some("rsa_pkcs1_sha384"),
        SignatureScheme::RsaPssRsaeSha512 => Some("rsa_pss_rsae_sha512"),
        SignatureScheme::RsaPkcs1Sha512 => Some("rsa_pkcs1_sha512"),
        _ => None,
    };
    require_supported("signature_schemes", scheme, mapped)
}

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
            grease = settings.grease,
            permute_extensions = settings.permute_extensions,
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
        builder
            .set_min_proto_version(Some(boring_version("min_version", settings.min_version)?))
            .map_err(|error| TlsError::backend("min_version", error))?;
        builder
            .set_max_proto_version(Some(boring_version("max_version", settings.max_version)?))
            .map_err(|error| TlsError::backend("max_version", error))?;

        builder.set_grease_enabled(settings.grease);
        builder.set_grease_sigalgs_enabled(settings.grease_signature_algorithms);
        builder.set_permute_extensions(settings.permute_extensions);
        builder.set_aes_hw_override(settings.aes_hardware);
        builder.clear_options(SslOptions::NO_TICKET);

        if settings.request_ocsp_staple {
            builder.enable_ocsp_stapling();
        }
        if settings.request_signed_certificate_timestamps {
            builder.enable_signed_cert_timestamps();
        }

        let groups = join_names(&settings.groups, group_name)?;
        builder
            .set_curves_list(&groups)
            .map_err(|error| TlsError::backend("groups", error))?;

        let signature_schemes = join_names(&settings.signature_schemes, signature_name)?;
        builder
            .set_sigalgs_list(&signature_schemes)
            .map_err(|error| TlsError::backend("signature_schemes", error))?;

        let cipher_suites = join_names(&settings.cipher_suites, cipher_name)?;
        builder.set_preserve_tls13_cipher_list(true);
        builder
            .set_cipher_list(&cipher_suites)
            .map_err(|error| TlsError::backend("cipher_suites", error))?;

        for algorithm in &settings.certificate_compression {
            match algorithm {
                CertificateCompression::Brotli => builder
                    .add_certificate_compression_algorithm(BrotliCertificateCompression)
                    .map_err(|error| TlsError::backend("certificate_compression", error))?,
                _ => {
                    return Err(TlsError::unsupported("certificate_compression", algorithm));
                }
            }
        }

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
                    .map(boring_key_share)
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

#[derive(Clone, Copy, Debug)]
struct BrotliCertificateCompression;

impl CertificateCompressor for BrotliCertificateCompression {
    const ALGORITHM: BoringCertificateCompressionAlgorithm =
        BoringCertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        brotli::BrotliDecompress(&mut io::Cursor::new(input), output)
    }
}

fn join_names<T>(
    values: &[T],
    name: impl Fn(T) -> Result<&'static str, TlsError>,
) -> Result<String, TlsError>
where
    T: Copy,
{
    values
        .iter()
        .copied()
        .map(name)
        .collect::<Result<Vec<_>, _>>()
        .map(|names| names.join(":"))
}

fn require_supported<T, U>(field: &'static str, value: T, mapped: Option<U>) -> Result<U, TlsError>
where
    T: fmt::Debug,
{
    mapped.ok_or_else(|| TlsError::unsupported(field, value))
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
