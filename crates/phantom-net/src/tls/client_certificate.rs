//! A client certificate chain and private key for TLS client authentication.

use std::{error::Error as StdError, fmt, sync::Arc};

use btls::{
    error::ErrorStack,
    nid::Nid,
    pkey::{Id, PKey, Private},
    ssl::SslRef,
    x509::X509,
};
use phantom_profile::SignatureScheme;
use phantom_quic_btls::QuicClientCertificate;
use zeroize::Zeroizing;

/// A certificate chain and the private key of its first certificate, which a
/// TLS client presents when a server asks for client authentication.
///
/// The key may be RSA or ECDSA (P-256, P-384, or P-521). The handshake signs
/// with a scheme that the key, the server's `CertificateRequest`, and the TLS
/// profile's `signature_schemes` all allow, because BoringSSL takes the
/// client's signing preferences from that list;
/// [`Self::check_signature_schemes`] tells whether a profile has one.
/// Ed25519 keys are rejected: a PKCS #8 v1 key parses but fails that check,
/// because no profile has an Ed25519 signature scheme, and a v2 key, which
/// carries its public key, fails to parse with kind
/// [`PrivateKey`](ClientCertificateErrorKind::PrivateKey), because BoringSSL
/// reads only version 0 of `PrivateKeyInfo`.
/// Cloning is cheap: clones share the parsed certificates and key.
///
/// A connector with a client certificate sends the same ClientHello as one
/// without. The certificate leaves the client only in answer to a
/// `CertificateRequest`, as a browser's does once a user has picked one.
#[derive(Clone)]
pub struct ClientCertificate {
    identity: Arc<Identity>,
}

struct Identity {
    certificate: X509,
    chain: Box<[X509]>,
    private_key: PKey<Private>,
    /// The same certificate, chain, and key for QUIC sessions.
    quic: QuicClientCertificate,
}

impl ClientCertificate {
    /// Parses a PEM certificate chain and an unencrypted PEM private key.
    ///
    /// `certificate_chain` holds one or more `CERTIFICATE` blocks, the client
    /// certificate first and then the intermediates to send with it.
    /// `private_key` holds one `PRIVATE KEY` (PKCS #8), `RSA PRIVATE KEY`, or
    /// `EC PRIVATE KEY` block.
    ///
    /// # Errors
    ///
    /// Returns a [`ClientCertificateError`] whose kind is
    /// [`Certificate`](ClientCertificateErrorKind::Certificate) when the chain
    /// has no certificate or one does not parse,
    /// [`PrivateKey`](ClientCertificateErrorKind::PrivateKey) when the key does
    /// not parse or has an unsupported type, and
    /// [`KeyMismatch`](ClientCertificateErrorKind::KeyMismatch) when the key
    /// does not belong to the first certificate.
    pub fn from_pem(
        certificate_chain: &[u8],
        private_key: &[u8],
    ) -> Result<Self, ClientCertificateError> {
        let chain = X509::stack_from_pem(certificate_chain).map_err(|error| {
            ClientCertificateError::with_source(
                ClientCertificateErrorKind::Certificate,
                "the certificate chain is not valid PEM",
                error,
            )
        })?;
        let private_key = PKey::private_key_from_pem(private_key).map_err(|error| {
            ClientCertificateError::with_source(
                ClientCertificateErrorKind::PrivateKey,
                "the private key is not an unencrypted PEM private key",
                error,
            )
        })?;
        Self::new(chain, private_key)
    }

    /// Parses a DER certificate chain and a DER private key.
    ///
    /// `certificate_chain` yields the client certificate first and then the
    /// intermediates to send with it. `private_key` is a PKCS #8
    /// `PrivateKeyInfo`, or an RSA or EC private key in its traditional
    /// encoding.
    ///
    /// # Errors
    ///
    /// Fails as [`Self::from_pem`] does.
    pub fn from_der<'a>(
        certificate_chain: impl IntoIterator<Item = &'a [u8]>,
        private_key: &[u8],
    ) -> Result<Self, ClientCertificateError> {
        let chain = certificate_chain
            .into_iter()
            .map(|der| {
                X509::from_der(der).map_err(|error| {
                    ClientCertificateError::with_source(
                        ClientCertificateErrorKind::Certificate,
                        "a certificate is not valid DER",
                        error,
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let private_key = PKey::private_key_from_der(private_key).map_err(|error| {
            ClientCertificateError::with_source(
                ClientCertificateErrorKind::PrivateKey,
                "the private key is not a DER private key",
                error,
            )
        })?;
        Self::new(chain, private_key)
    }

    fn new(chain: Vec<X509>, private_key: PKey<Private>) -> Result<Self, ClientCertificateError> {
        let mut chain = chain.into_iter();
        let Some(certificate) = chain.next() else {
            return Err(ClientCertificateError::new(
                ClientCertificateErrorKind::Certificate,
                "the certificate chain holds no certificate",
            ));
        };
        if ![Id::RSA, Id::EC, Id::ED25519].contains(&private_key.id()) {
            return Err(ClientCertificateError::new(
                ClientCertificateErrorKind::PrivateKey,
                "the private key is not an RSA, ECDSA, or Ed25519 key",
            ));
        }
        let public_key = certificate.public_key().map_err(|error| {
            ClientCertificateError::with_source(
                ClientCertificateErrorKind::Certificate,
                "the certificate's public key cannot be read",
                error,
            )
        })?;
        if !public_key.public_eq(&private_key) {
            return Err(ClientCertificateError::new(
                ClientCertificateErrorKind::KeyMismatch,
                "the private key does not match the first certificate",
            ));
        }
        let chain: Box<[X509]> = chain.collect();
        let quic = quic_certificate(&certificate, &chain, &private_key)?;
        Ok(Self {
            identity: Arc::new(Identity {
                certificate,
                chain,
                private_key,
                quic,
            }),
        })
    }

    /// Checks that a TLS profile whose `signature_schemes` are `schemes` can
    /// sign with this certificate's key.
    ///
    /// An RSA key needs an RSA PKCS #1 or RSA-PSS (RSAE) scheme. An ECDSA key
    /// needs the scheme of its curve, as TLS 1.3 requires: P-256 needs
    /// `EcdsaSecp256r1Sha256`, P-384 `EcdsaSecp384r1Sha384`, and P-521
    /// `EcdsaSecp521r1Sha512`. An Ed25519 key needs an Ed25519 scheme, which
    /// [`SignatureScheme`] does not have.
    ///
    /// # Errors
    ///
    /// Returns a [`ClientCertificateError`] of kind
    /// [`SignatureScheme`](ClientCertificateErrorKind::SignatureScheme) when
    /// no scheme in `schemes` fits the key.
    pub fn check_signature_schemes(
        &self,
        schemes: &[SignatureScheme],
    ) -> Result<(), ClientCertificateError> {
        let key = &self.identity.private_key;
        let fits = |scheme: &SignatureScheme| match key.id() {
            Id::RSA => matches!(
                scheme,
                SignatureScheme::RsaPkcs1Sha256
                    | SignatureScheme::RsaPkcs1Sha384
                    | SignatureScheme::RsaPkcs1Sha512
                    | SignatureScheme::RsaPssRsaeSha256
                    | SignatureScheme::RsaPssRsaeSha384
                    | SignatureScheme::RsaPssRsaeSha512
            ),
            Id::EC => {
                let curve = key.ec_key().ok().and_then(|key| key.group().curve_name());
                matches!(
                    (curve, scheme),
                    (
                        Some(Nid::X9_62_PRIME256V1),
                        SignatureScheme::EcdsaSecp256r1Sha256
                    ) | (Some(Nid::SECP384R1), SignatureScheme::EcdsaSecp384r1Sha384)
                        | (Some(Nid::SECP521R1), SignatureScheme::EcdsaSecp521r1Sha512)
                )
            }
            _ => false,
        };
        if schemes.iter().any(fits) {
            Ok(())
        } else {
            Err(ClientCertificateError::new(
                ClientCertificateErrorKind::SignatureScheme,
                "no signature scheme of the TLS profile can sign with the private key",
            ))
        }
    }

    /// Returns the certificate, chain, and key in the QUIC adapter's form.
    pub(crate) fn quic(&self) -> &QuicClientCertificate {
        &self.identity.quic
    }

    /// Installs the certificate, its chain, and its key on one connection.
    pub(crate) fn apply(&self, ssl: &mut SslRef) -> Result<(), ErrorStack> {
        ssl.set_certificate(&self.identity.certificate)?;
        ssl.set_private_key(&self.identity.private_key)?;
        for certificate in &self.identity.chain {
            ssl.add_chain_cert(certificate)?;
        }
        Ok(())
    }
}

/// Hands the parsed certificate, chain, and key to the QUIC adapter as DER.
fn quic_certificate(
    certificate: &X509,
    chain: &[X509],
    private_key: &PKey<Private>,
) -> Result<QuicClientCertificate, ClientCertificateError> {
    let certificates = std::iter::once(certificate)
        .chain(chain)
        .map(|certificate| certificate.to_der())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ClientCertificateError::with_source(
                ClientCertificateErrorKind::Certificate,
                "the certificate chain cannot be encoded for QUIC",
                error,
            )
        })?;
    // PKCS #8 is the one DER form that holds every supported key type,
    // Ed25519 included.
    let key = Zeroizing::new(private_key.private_key_to_der_pkcs8().map_err(|error| {
        ClientCertificateError::with_source(
            ClientCertificateErrorKind::PrivateKey,
            "the private key cannot be encoded for QUIC",
            error,
        )
    })?);
    QuicClientCertificate::from_der(certificates.iter().map(Vec::as_slice), &key).map_err(|error| {
        ClientCertificateError::with_source(
            ClientCertificateErrorKind::Certificate,
            "the QUIC adapter rejected the certificate chain",
            error,
        )
    })
}

impl fmt::Debug for ClientCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientCertificate")
            .field("intermediate_count", &self.identity.chain.len())
            .finish_non_exhaustive()
    }
}

/// Why a [`ClientCertificate`] could not be built.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ClientCertificateErrorKind {
    /// The certificate chain is empty or a certificate does not parse.
    Certificate,
    /// The private key does not parse or has an unsupported type.
    PrivateKey,
    /// The private key does not belong to the first certificate.
    KeyMismatch,
    /// No signature scheme of a TLS profile can sign with the private key.
    SignatureScheme,
}

/// Error returned when a client certificate or its key cannot be used.
#[derive(Debug)]
pub struct ClientCertificateError {
    kind: ClientCertificateErrorKind,
    message: &'static str,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl ClientCertificateError {
    const fn new(kind: ClientCertificateErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
        }
    }

    fn with_source(
        kind: ClientCertificateErrorKind,
        message: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message,
            source: Some(Box::new(source)),
        }
    }

    /// Returns the stable category of this error.
    #[must_use]
    pub const fn kind(&self) -> ClientCertificateErrorKind {
        self.kind
    }
}

impl fmt::Display for ClientCertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid client certificate: {}", self.message)
    }
}

impl StdError for ClientCertificateError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}
