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
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as BoringStream;
use tracing::{Instrument, debug, debug_span};

/// A TLS protocol version accepted by the connector.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum TlsVersion {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

impl TlsVersion {
    fn boring(self) -> SslVersion {
        match self {
            Self::Tls12 => SslVersion::TLS1_2,
            Self::Tls13 => SslVersion::TLS1_3,
        }
    }
}

/// A TLS cipher suite in wire preference order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256.
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384.
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256.
    Chacha20Poly1305Sha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
    EcdheEcdsaAes128GcmSha256,
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.
    EcdheRsaAes128GcmSha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.
    EcdheEcdsaAes256GcmSha384,
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.
    EcdheRsaAes256GcmSha384,
    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
    EcdheEcdsaChacha20Poly1305Sha256,
    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.
    EcdheRsaChacha20Poly1305Sha256,
    /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.
    EcdheRsaAes128CbcSha,
    /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.
    EcdheRsaAes256CbcSha,
    /// TLS_RSA_WITH_AES_128_GCM_SHA256.
    RsaAes128GcmSha256,
    /// TLS_RSA_WITH_AES_256_GCM_SHA384.
    RsaAes256GcmSha384,
    /// TLS_RSA_WITH_AES_128_CBC_SHA.
    RsaAes128CbcSha,
    /// TLS_RSA_WITH_AES_256_CBC_SHA.
    RsaAes256CbcSha,
}

impl CipherSuite {
    fn boring_name(self) -> &'static str {
        match self {
            Self::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            Self::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            Self::Chacha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
            Self::EcdheEcdsaAes128GcmSha256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            Self::EcdheRsaAes128GcmSha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            Self::EcdheEcdsaAes256GcmSha384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            Self::EcdheRsaAes256GcmSha384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            Self::EcdheEcdsaChacha20Poly1305Sha256 => {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            Self::EcdheRsaChacha20Poly1305Sha256 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            Self::EcdheRsaAes128CbcSha => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            Self::EcdheRsaAes256CbcSha => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            Self::RsaAes128GcmSha256 => "TLS_RSA_WITH_AES_128_GCM_SHA256",
            Self::RsaAes256GcmSha384 => "TLS_RSA_WITH_AES_256_GCM_SHA384",
            Self::RsaAes128CbcSha => "TLS_RSA_WITH_AES_128_CBC_SHA",
            Self::RsaAes256CbcSha => "TLS_RSA_WITH_AES_256_CBC_SHA",
        }
    }
}

/// A TLS supported group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NamedGroup {
    /// Hybrid X25519 and ML-KEM-768.
    X25519MlKem768,
    /// X25519.
    X25519,
    /// NIST P-256.
    Secp256r1,
    /// NIST P-384.
    Secp384r1,
}

impl NamedGroup {
    fn boring_name(self) -> &'static str {
        match self {
            Self::X25519MlKem768 => "X25519MLKEM768",
            Self::X25519 => "X25519",
            Self::Secp256r1 => "P-256",
            Self::Secp384r1 => "P-384",
        }
    }

    fn boring_key_share(self) -> KeyShare {
        match self {
            Self::X25519MlKem768 => KeyShare::X25519_MLKEM768,
            Self::X25519 => KeyShare::X25519,
            Self::Secp256r1 => KeyShare::P256,
            Self::Secp384r1 => KeyShare::P384,
        }
    }
}

/// A TLS signature scheme in wire preference order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignatureScheme {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
    /// ECDSA P-256 with SHA-256.
    EcdsaSecp256r1Sha256,
    /// RSA-PSS with an RSAE key and SHA-256.
    RsaPssRsaeSha256,
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaPkcs1Sha256,
    /// ECDSA P-384 with SHA-384.
    EcdsaSecp384r1Sha384,
    /// RSA-PSS with an RSAE key and SHA-384.
    RsaPssRsaeSha384,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSA-PSS with an RSAE key and SHA-512.
    RsaPssRsaeSha512,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaPkcs1Sha512,
}

impl SignatureScheme {
    fn boring_name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "mldsa44",
            Self::MlDsa65 => "mldsa65",
            Self::MlDsa87 => "mldsa87",
            Self::EcdsaSecp256r1Sha256 => "ecdsa_secp256r1_sha256",
            Self::RsaPssRsaeSha256 => "rsa_pss_rsae_sha256",
            Self::RsaPkcs1Sha256 => "rsa_pkcs1_sha256",
            Self::EcdsaSecp384r1Sha384 => "ecdsa_secp384r1_sha384",
            Self::RsaPssRsaeSha384 => "rsa_pss_rsae_sha384",
            Self::RsaPkcs1Sha384 => "rsa_pkcs1_sha384",
            Self::RsaPssRsaeSha512 => "rsa_pss_rsae_sha512",
            Self::RsaPkcs1Sha512 => "rsa_pkcs1_sha512",
        }
    }
}

/// A certificate compression algorithm advertised by the TLS client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CertificateCompression {
    /// Brotli certificate compression.
    Brotli,
}

/// ALPS configuration for one ALPN protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AlpsSettings {
    /// ALPN protocol identifier receiving application settings.
    pub(crate) protocol: Box<[u8]>,
    /// Whether to use the final ALPS extension codepoint.
    pub(crate) use_new_codepoint: bool,
}

/// Ordered TLS settings independent of the concrete TLS backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TlsSettings {
    /// Smallest accepted TLS version.
    pub(crate) min_version: TlsVersion,
    /// Largest accepted TLS version.
    pub(crate) max_version: TlsVersion,
    /// Cipher suites in preference order.
    pub(crate) cipher_suites: Vec<CipherSuite>,
    /// Supported groups in preference order.
    pub(crate) groups: Vec<NamedGroup>,
    /// Initial key shares in wire order.
    pub(crate) key_shares: Vec<NamedGroup>,
    /// Signature schemes in preference order.
    pub(crate) signature_schemes: Vec<SignatureScheme>,
    /// ALPN protocol identifiers in preference order.
    pub(crate) alpn_protocols: Vec<Box<[u8]>>,
    /// Optional ALPS advertisement.
    pub(crate) alps: Option<AlpsSettings>,
    /// Certificate compression algorithms in preference order.
    pub(crate) certificate_compression: Vec<CertificateCompression>,
    /// Whether ordinary TLS GREASE is enabled.
    pub(crate) grease: bool,
    /// Whether signature-algorithm GREASE is enabled.
    pub(crate) grease_signature_algorithms: bool,
    /// Whether eligible ClientHello extensions are randomized.
    pub(crate) permute_extensions: bool,
    /// Whether to emit a GREASE ECH extension without an ECH configuration.
    pub(crate) ech_grease: bool,
    /// Whether to request an OCSP staple.
    pub(crate) request_ocsp_staple: bool,
    /// Whether to request signed certificate timestamps.
    pub(crate) request_signed_certificate_timestamps: bool,
    /// Whether the client should be treated as having AES hardware.
    pub(crate) aes_hardware: bool,
}

impl TlsSettings {
    fn validate(&self) -> Result<(), TlsError> {
        if self.min_version > self.max_version {
            return Err(TlsError::configuration(
                "version range",
                "minimum TLS version exceeds maximum TLS version",
            ));
        }
        if self.cipher_suites.is_empty() {
            return Err(TlsError::configuration(
                "cipher_suites",
                "at least one cipher suite is required",
            ));
        }
        if self.groups.is_empty() {
            return Err(TlsError::configuration(
                "groups",
                "at least one supported group is required",
            ));
        }
        if self.key_shares.is_empty() {
            return Err(TlsError::configuration(
                "key_shares",
                "at least one initial key share is required",
            ));
        }
        if let Some(group) = self
            .key_shares
            .iter()
            .find(|group| !self.groups.contains(group))
        {
            return Err(TlsError::configuration(
                "key_shares",
                format!("key share {group:?} is absent from supported groups"),
            ));
        }
        if self.signature_schemes.is_empty() {
            return Err(TlsError::configuration(
                "signature_schemes",
                "at least one signature scheme is required",
            ));
        }
        encode_alpn(&self.alpn_protocols)?;

        if let Some(alps) = &self.alps {
            if !self
                .alpn_protocols
                .iter()
                .any(|protocol| protocol.as_ref() == alps.protocol.as_ref())
            {
                return Err(TlsError::configuration(
                    "alps.protocol",
                    "ALPS protocol is absent from the ALPN protocol list",
                ));
            }
        }

        if self.certificate_compression.len() > 1 {
            return Err(TlsError::configuration(
                "certificate_compression",
                "Brotli certificate compression must not repeat",
            ));
        }

        Ok(())
    }
}

/// A reusable TLS connector with a validated immutable configuration.
#[derive(Clone)]
pub(crate) struct TlsConnector {
    backend: BoringConnector,
    alpn_wire: Box<[u8]>,
    alps: Option<AlpsSettings>,
    key_shares: Box<[NamedGroup]>,
    ech_grease: bool,
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsConnector")
            .field("alpn_protocol_count", &count_alpn(&self.alpn_wire))
            .field("alps", &self.alps)
            .field("key_shares", &self.key_shares)
            .field("ech_grease", &self.ech_grease)
            .finish_non_exhaustive()
    }
}

impl TlsConnector {
    /// Builds a connector, rejecting invalid or unsupported settings immediately.
    pub(crate) fn new(settings: &TlsSettings) -> Result<Self, TlsError> {
        settings.validate()?;

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
        );
        let _entered = span.enter();
        debug!("building TLS connector");

        let mut builder = BoringConnector::builder(SslMethod::tls())
            .map_err(|error| TlsError::backend("trust store", error))?;
        builder.set_verify(SslVerifyMode::PEER);
        builder
            .set_min_proto_version(Some(settings.min_version.boring()))
            .map_err(|error| TlsError::backend("min_version", error))?;
        builder
            .set_max_proto_version(Some(settings.max_version.boring()))
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

        let groups = join_names(&settings.groups, NamedGroup::boring_name);
        builder
            .set_curves_list(&groups)
            .map_err(|error| TlsError::backend("groups", error))?;

        let signature_schemes =
            join_names(&settings.signature_schemes, SignatureScheme::boring_name);
        builder
            .set_sigalgs_list(&signature_schemes)
            .map_err(|error| TlsError::backend("signature_schemes", error))?;

        let cipher_suites = join_names(&settings.cipher_suites, CipherSuite::boring_name);
        builder.set_preserve_tls13_cipher_list(true);
        builder
            .set_cipher_list(&cipher_suites)
            .map_err(|error| TlsError::backend("cipher_suites", error))?;

        for algorithm in &settings.certificate_compression {
            match algorithm {
                CertificateCompression::Brotli => builder
                    .add_certificate_compression_algorithm(BrotliCertificateCompression)
                    .map_err(|error| TlsError::backend("certificate_compression", error))?,
            }
        }

        let alpn_wire = encode_alpn(&settings.alpn_protocols)?;
        debug!("TLS connector built");

        Ok(Self {
            backend: builder.build(),
            alpn_wire,
            alps: settings.alps.clone(),
            key_shares: settings.key_shares.clone().into_boxed_slice(),
            ech_grease: settings.ech_grease,
        })
    }

    /// Performs a TLS client handshake over an already-connected byte stream.
    pub(crate) async fn connect<S>(
        &self,
        server_name: &str,
        stream: S,
        required_alpn: &[u8],
    ) -> Result<TlsStream<S>, TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let span = debug_span!(
            "tls.handshake",
            server_name = server_name,
            alpn_protocol_count = count_alpn(&self.alpn_wire),
        );
        async {
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
                    .add_application_settings(&alps.protocol)
                    .map_err(|error| TlsError::backend("alps.protocol", error))?;
                configuration.set_alps_use_new_codepoint(alps.use_new_codepoint);
            }

            let key_shares = self
                .key_shares
                .iter()
                .copied()
                .map(NamedGroup::boring_key_share)
                .collect::<Vec<_>>();
            configuration
                .set_client_key_shares(&key_shares)
                .map_err(|error| TlsError::backend("key_shares", error))?;

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
            ensure_alpn(negotiated_alpn.as_deref(), required_alpn).inspect_err(|_| {
                debug!("TLS handshake negotiated an unexpected ALPN protocol");
            })?;
            debug!(
                negotiated_alpn = negotiated_alpn
                    .as_deref()
                    .and_then(recognized_alpn_name)
                    .unwrap_or("other-or-none"),
                "TLS handshake completed"
            );
            Ok(TlsStream {
                inner: stream,
                negotiated_alpn,
            })
        }
        .instrument(span)
        .await
    }
}

/// A connected TLS stream that hides its BoringSSL representation.
pub(crate) struct TlsStream<S> {
    inner: BoringStream<S>,
    negotiated_alpn: Option<Box<[u8]>>,
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

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Category of a TLS connection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlsErrorKind {
    /// Settings were internally inconsistent or incomplete.
    InvalidConfiguration,
    /// The configured TLS backend rejected a setting.
    BackendConfiguration,
    /// The TLS handshake failed.
    Handshake,
    /// The server selected a different application protocol.
    AlpnMismatch,
}

/// Error returned while constructing or using the TLS connector.
#[derive(Debug)]
pub(crate) struct TlsError {
    kind: TlsErrorKind,
    field: Option<&'static str>,
    message: Box<str>,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl TlsError {
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

    fn handshake(source: btls::ssl::Error) -> Self {
        Self {
            kind: TlsErrorKind::Handshake,
            field: None,
            message: "TLS handshake failed".into(),
            source: Some(Box::new(source)),
        }
    }

    fn alpn_mismatch(required: &[u8], negotiated: Option<&[u8]>) -> Self {
        let required = display_alpn(required);
        let negotiated = negotiated.map_or_else(|| "none".to_owned(), display_alpn);
        Self {
            kind: TlsErrorKind::AlpnMismatch,
            field: Some("alpn_protocols"),
            message: format!("required ALPN {required}, but server negotiated {negotiated}").into(),
            source: None,
        }
    }

    /// Returns the broad failure category without exposing backend types.
    pub(crate) fn kind(&self) -> TlsErrorKind {
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

fn join_names<T>(values: &[T], name: impl Fn(T) -> &'static str) -> String
where
    T: Copy,
{
    values
        .iter()
        .copied()
        .map(name)
        .collect::<Vec<_>>()
        .join(":")
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

fn display_alpn(protocol: &[u8]) -> String {
    recognized_alpn_name(protocol)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "0x{}",
                protocol
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        })
}

fn ensure_alpn(negotiated: Option<&[u8]>, required: &[u8]) -> Result<(), TlsError> {
    if negotiated == Some(required) {
        Ok(())
    } else {
        Err(TlsError::alpn_mismatch(required, negotiated))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, error::Error, time::Duration};

    use phantom_testkit::tls::{CaptureLimits, capture_client_hello, is_grease};
    use tokio::{net::TcpListener, time::Instant};

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn chromium_150_windows() -> TlsSettings {
        TlsSettings {
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            cipher_suites: vec![
                CipherSuite::Aes128GcmSha256,
                CipherSuite::Aes256GcmSha384,
                CipherSuite::Chacha20Poly1305Sha256,
                CipherSuite::EcdheEcdsaAes128GcmSha256,
                CipherSuite::EcdheRsaAes128GcmSha256,
                CipherSuite::EcdheEcdsaAes256GcmSha384,
                CipherSuite::EcdheRsaAes256GcmSha384,
                CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
                CipherSuite::EcdheRsaChacha20Poly1305Sha256,
                CipherSuite::EcdheRsaAes128CbcSha,
                CipherSuite::EcdheRsaAes256CbcSha,
                CipherSuite::RsaAes128GcmSha256,
                CipherSuite::RsaAes256GcmSha384,
                CipherSuite::RsaAes128CbcSha,
                CipherSuite::RsaAes256CbcSha,
            ],
            groups: vec![
                NamedGroup::X25519MlKem768,
                NamedGroup::X25519,
                NamedGroup::Secp256r1,
                NamedGroup::Secp384r1,
            ],
            key_shares: vec![NamedGroup::X25519MlKem768, NamedGroup::X25519],
            signature_schemes: vec![
                SignatureScheme::MlDsa44,
                SignatureScheme::MlDsa65,
                SignatureScheme::MlDsa87,
                SignatureScheme::EcdsaSecp256r1Sha256,
                SignatureScheme::RsaPssRsaeSha256,
                SignatureScheme::RsaPkcs1Sha256,
                SignatureScheme::EcdsaSecp384r1Sha384,
                SignatureScheme::RsaPssRsaeSha384,
                SignatureScheme::RsaPkcs1Sha384,
                SignatureScheme::RsaPssRsaeSha512,
                SignatureScheme::RsaPkcs1Sha512,
            ],
            alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
            alps: Some(AlpsSettings {
                protocol: Box::from(&b"h2"[..]),
                use_new_codepoint: true,
            }),
            certificate_compression: vec![CertificateCompression::Brotli],
            grease: true,
            grease_signature_algorithms: false,
            permute_extensions: true,
            ech_grease: true,
            request_ocsp_staple: true,
            request_signed_certificate_timestamps: true,
            aes_hardware: true,
        }
    }

    #[tokio::test]
    async fn emits_the_configured_client_hello() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let capture_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            capture_client_hello(
                &mut stream,
                Instant::now() + TEST_TIMEOUT,
                CaptureLimits::new(32 * 1024, 40 * 1024, 4),
            )
            .await
            .map_err(io::Error::other)
        });

        let connector = TlsConnector::new(&chromium_150_windows())?;
        let tcp =
            tokio::time::timeout(TEST_TIMEOUT, tokio::net::TcpStream::connect(address)).await??;
        let handshake = tokio::time::timeout(
            TEST_TIMEOUT,
            connector.connect("example.test", tcp, b"http/1.1"),
        );
        let handshake_error = match handshake.await? {
            Ok(_) => return Err("capture peer unexpectedly completed TLS".into()),
            Err(error) => error,
        };
        assert_eq!(handshake_error.kind(), TlsErrorKind::Handshake);

        let capture = tokio::time::timeout(TEST_TIMEOUT, capture_task).await???;
        let summary = capture.summary()?;

        assert_eq!(summary.legacy_version(), 0x0303);
        assert_eq!(
            without_grease(summary.cipher_suites()),
            vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ]
        );
        assert_eq!(
            without_grease(summary.supported_groups()),
            vec![0x11ec, 0x001d, 0x0017, 0x0018]
        );
        assert_eq!(
            summary.signature_algorithms(),
            &[
                0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                0x0601
            ]
        );
        assert_eq!(
            summary.alpn_protocols(),
            &[b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(
            without_grease(summary.supported_versions()),
            vec![0x0304, 0x0303]
        );
        assert_eq!(
            without_grease(summary.key_share_groups()),
            vec![0x11ec, 0x001d]
        );

        assert!(summary.cipher_suites().iter().copied().any(is_grease));
        assert!(summary.supported_groups().iter().copied().any(is_grease));
        assert!(summary.supported_versions().iter().copied().any(is_grease));
        assert!(summary.key_share_groups().iter().copied().any(is_grease));
        assert!(summary.extension_types().iter().copied().any(is_grease));

        // Extension permutation is intentionally randomized. Assert membership,
        // uniqueness, and the exact stable set rather than a fictitious order.
        let actual_extensions = summary
            .extension_types()
            .iter()
            .copied()
            .filter(|extension| !is_grease(*extension))
            .collect::<BTreeSet<_>>();
        let expected_extensions = BTreeSet::from([
            0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 0xfe0d, 0xff01,
        ]);
        assert_eq!(actual_extensions, expected_extensions);

        Ok(())
    }

    #[test]
    fn invalid_settings_fail_before_stream_io() -> Result<(), Box<dyn Error>> {
        let mut settings = chromium_150_windows();
        settings.alpn_protocols = vec![Box::default()];

        let error = match TlsConnector::new(&settings) {
            Ok(_) => return Err("empty ALPN unexpectedly built a connector".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), TlsErrorKind::InvalidConfiguration);
        assert!(error.to_string().contains("alpn_protocols"));
        Ok(())
    }

    #[test]
    fn alpn_mismatch_distinguishes_http2_from_http1() -> Result<(), Box<dyn Error>> {
        let error = match ensure_alpn(Some(b"h2"), b"http/1.1") {
            Ok(()) => return Err("HTTP/2 unexpectedly satisfied an HTTP/1.1 requirement".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), TlsErrorKind::AlpnMismatch);
        assert!(error.to_string().contains("h2"));
        Ok(())
    }

    fn without_grease(values: &[u16]) -> Vec<u16> {
        values
            .iter()
            .copied()
            .filter(|value| !is_grease(*value))
            .collect()
    }
}
