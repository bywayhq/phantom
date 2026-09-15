//! Translation from browser-neutral TLS settings to BoringSSL configuration.

use std::fmt;

use btls::ssl::{ExtensionType, KeyShare, SslConnectorBuilder, SslOptions, SslVersion};
use phantom_profile::{
    CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
    NamedGroup, SignatureScheme, TlsSettings, TlsVersion,
};

use super::{
    TlsError,
    compression::{
        BrotliCertificateCompression, ZlibCertificateCompression, ZstdCertificateCompression,
    },
};

pub(super) fn apply(
    builder: &mut SslConnectorBuilder,
    settings: &TlsSettings,
) -> Result<(), TlsError> {
    builder
        .set_min_proto_version(Some(version("min_version", settings.min_version)?))
        .map_err(|error| TlsError::backend("min_version", error))?;
    builder
        .set_max_proto_version(Some(version("max_version", settings.max_version)?))
        .map_err(|error| TlsError::backend("max_version", error))?;

    builder.set_grease_enabled(settings.grease);
    builder.set_grease_sigalgs_enabled(settings.grease_signature_algorithms);
    if let Some(limit) = settings.record_size_limit {
        builder
            .set_record_size_limit(limit)
            .map_err(|error| TlsError::backend("record_size_limit", error))?;
    }
    apply_extension_order(builder, &settings.extension_order)?;
    builder.set_aes_hw_override(settings.aes_hardware);
    if settings.session_tickets {
        builder.clear_options(SslOptions::NO_TICKET);
    } else {
        builder.set_options(SslOptions::NO_TICKET);
    }

    if settings.request_ocsp_staple {
        builder.enable_ocsp_stapling();
    }
    if settings.request_signed_certificate_timestamps {
        builder.enable_signed_cert_timestamps();
    }

    builder
        .set_curves_list(&join_names(&settings.groups, group_name)?)
        .map_err(|error| TlsError::backend("groups", error))?;
    builder
        .set_sigalgs_list(&join_names(&settings.signature_schemes, signature_name)?)
        .map_err(|error| TlsError::backend("signature_schemes", error))?;

    builder.set_preserve_tls13_cipher_list(true);
    builder
        .set_cipher_list(&join_names(&settings.cipher_suites, cipher_name)?)
        .map_err(|error| TlsError::backend("cipher_suites", error))?;

    for algorithm in &settings.certificate_compression {
        match algorithm {
            CertificateCompression::Zlib => builder
                .add_certificate_compression_algorithm(ZlibCertificateCompression)
                .map_err(|error| TlsError::backend("certificate_compression", error))?,
            CertificateCompression::Brotli => builder
                .add_certificate_compression_algorithm(BrotliCertificateCompression)
                .map_err(|error| TlsError::backend("certificate_compression", error))?,
            CertificateCompression::Zstd => builder
                .add_certificate_compression_algorithm(ZstdCertificateCompression)
                .map_err(|error| TlsError::backend("certificate_compression", error))?,
            _ => return Err(TlsError::unsupported("certificate_compression", algorithm)),
        }
    }

    Ok(())
}

pub(super) fn key_share(group: NamedGroup) -> Result<KeyShare, TlsError> {
    let mapped = match group {
        NamedGroup::X25519MlKem768 => Some(KeyShare::X25519_MLKEM768),
        NamedGroup::X25519 => Some(KeyShare::X25519),
        NamedGroup::Secp256r1 => Some(KeyShare::P256),
        NamedGroup::Secp384r1 => Some(KeyShare::P384),
        NamedGroup::Secp521r1 => Some(KeyShare::P521),
        NamedGroup::Ffdhe2048 => Some(KeyShare::FFDHE2048),
        NamedGroup::Ffdhe3072 => Some(KeyShare::FFDHE3072),
        _ => None,
    };
    require_supported("key_shares", group, mapped)
}

pub(super) fn extension_order_trace_name(order: &ClientHelloExtensionOrder) -> &'static str {
    match order {
        ClientHelloExtensionOrder::BackendDefault => "backend_default",
        ClientHelloExtensionOrder::Permuted => "permuted",
        ClientHelloExtensionOrder::Fixed(_) => "fixed",
        _ => "unsupported",
    }
}

fn version(field: &'static str, version: TlsVersion) -> Result<SslVersion, TlsError> {
    let mapped = match version {
        TlsVersion::Tls10 => Some(SslVersion::TLS1),
        TlsVersion::Tls11 => Some(SslVersion::TLS1_1),
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
        CipherSuite::EcdheEcdsaAes128CbcSha => Some("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
        CipherSuite::EcdheEcdsaAes256CbcSha => Some("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
        CipherSuite::EcdheEcdsa3DesEdeCbcSha => Some("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
        CipherSuite::EcdheRsa3DesEdeCbcSha => Some("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
        CipherSuite::RsaAes128GcmSha256 => Some("TLS_RSA_WITH_AES_128_GCM_SHA256"),
        CipherSuite::RsaAes256GcmSha384 => Some("TLS_RSA_WITH_AES_256_GCM_SHA384"),
        CipherSuite::RsaAes128CbcSha => Some("TLS_RSA_WITH_AES_128_CBC_SHA"),
        CipherSuite::RsaAes256CbcSha => Some("TLS_RSA_WITH_AES_256_CBC_SHA"),
        CipherSuite::Rsa3DesEdeCbcSha => Some("TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
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
        NamedGroup::Secp521r1 => Some("P-521"),
        NamedGroup::Ffdhe2048 => Some("ffdhe2048"),
        NamedGroup::Ffdhe3072 => Some("ffdhe3072"),
        _ => None,
    };
    require_supported("groups", group, mapped)
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
        SignatureScheme::EcdsaSecp521r1Sha512 => Some("ecdsa_secp521r1_sha512"),
        SignatureScheme::RsaPssRsaeSha384 => Some("rsa_pss_rsae_sha384"),
        SignatureScheme::RsaPkcs1Sha384 => Some("rsa_pkcs1_sha384"),
        SignatureScheme::RsaPssRsaeSha512 => Some("rsa_pss_rsae_sha512"),
        SignatureScheme::RsaPkcs1Sha512 => Some("rsa_pkcs1_sha512"),
        SignatureScheme::EcdsaSha1 => Some("ecdsa_sha1"),
        SignatureScheme::RsaPkcs1Sha1 => Some("rsa_pkcs1_sha1"),
        _ => None,
    };
    require_supported("signature_schemes", scheme, mapped)
}

fn apply_extension_order(
    builder: &mut SslConnectorBuilder,
    order: &ClientHelloExtensionOrder,
) -> Result<(), TlsError> {
    match order {
        ClientHelloExtensionOrder::BackendDefault => builder.set_permute_extensions(false),
        ClientHelloExtensionOrder::Permuted => builder.set_permute_extensions(true),
        ClientHelloExtensionOrder::Fixed(extensions) => {
            builder.set_permute_extensions(false);
            let extensions = extensions
                .iter()
                .copied()
                .map(extension_type)
                .collect::<Result<Vec<_>, _>>()?;
            builder
                .set_extension_permutation(&extensions)
                .map_err(|error| TlsError::backend("extension_order", error))?;
        }
        _ => return Err(TlsError::unsupported("extension_order", order)),
    }
    Ok(())
}

fn extension_type(extension: ClientHelloExtension) -> Result<ExtensionType, TlsError> {
    let mapped = match extension {
        ClientHelloExtension::ServerName => Some(ExtensionType::SERVER_NAME),
        ClientHelloExtension::ExtendedMasterSecret => Some(ExtensionType::EXTENDED_MASTER_SECRET),
        ClientHelloExtension::RenegotiationInfo => Some(ExtensionType::RENEGOTIATE),
        ClientHelloExtension::SupportedGroups => Some(ExtensionType::SUPPORTED_GROUPS),
        ClientHelloExtension::EcPointFormats => Some(ExtensionType::EC_POINT_FORMATS),
        ClientHelloExtension::SessionTicket => Some(ExtensionType::SESSION_TICKET),
        ClientHelloExtension::RecordSizeLimit => Some(ExtensionType::RECORD_SIZE_LIMIT),
        ClientHelloExtension::Alpn => Some(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        ClientHelloExtension::StatusRequest => Some(ExtensionType::STATUS_REQUEST),
        ClientHelloExtension::SignedCertificateTimestamp => {
            Some(ExtensionType::CERTIFICATE_TIMESTAMP)
        }
        ClientHelloExtension::KeyShare => Some(ExtensionType::KEY_SHARE),
        ClientHelloExtension::SupportedVersions => Some(ExtensionType::SUPPORTED_VERSIONS),
        ClientHelloExtension::SignatureAlgorithms => Some(ExtensionType::SIGNATURE_ALGORITHMS),
        ClientHelloExtension::PskKeyExchangeModes => Some(ExtensionType::PSK_KEY_EXCHANGE_MODES),
        ClientHelloExtension::CertificateCompression => Some(ExtensionType::CERT_COMPRESSION),
        ClientHelloExtension::TrustAnchors => Some(ExtensionType::TRUST_ANCHORS),
        ClientHelloExtension::ApplicationSettings => Some(ExtensionType::APPLICATION_SETTINGS),
        ClientHelloExtension::ApplicationSettingsLegacy => {
            Some(ExtensionType::APPLICATION_SETTINGS_OLD)
        }
        ClientHelloExtension::EncryptedClientHello => Some(ExtensionType::ENCRYPTED_CLIENT_HELLO),
        _ => None,
    };
    require_supported("extension_order", extension, mapped)
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

pub(super) fn require_supported<T, U>(
    field: &'static str,
    value: T,
    mapped: Option<U>,
) -> Result<U, TlsError>
where
    T: fmt::Debug,
{
    mapped.ok_or_else(|| TlsError::unsupported(field, value))
}
