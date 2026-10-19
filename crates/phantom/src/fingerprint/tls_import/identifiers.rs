//! Supported IANA identifiers. Unknown values fail rather than disappearing.

use super::{Kind, Result, error};
use phantom_profile::{CipherSuite, ClientHelloExtension, NamedGroup, SignatureScheme};

pub(in crate::fingerprint) fn cipher(id: u16) -> Result<CipherSuite> {
    CipherSuite::from_iana_id(id)
        .ok_or_else(|| error(Kind::UnsupportedSetting, "tls.cipher_suites"))
}

pub(in crate::fingerprint) fn group(id: u16) -> Result<NamedGroup> {
    use NamedGroup::*;
    Ok(match id {
        4588 => X25519MlKem768,
        29 => X25519,
        23 => Secp256r1,
        24 => Secp384r1,
        25 => Secp521r1,
        256 => Ffdhe2048,
        257 => Ffdhe3072,
        _ => return Err(error(Kind::UnsupportedSetting, "tls.groups")),
    })
}

pub(in crate::fingerprint) fn signature(id: u16) -> Result<SignatureScheme> {
    use SignatureScheme::*;
    Ok(match id {
        0x0904 => MlDsa44,
        0x0905 => MlDsa65,
        0x0906 => MlDsa87,
        0x0403 => EcdsaSecp256r1Sha256,
        0x0503 => EcdsaSecp384r1Sha384,
        0x0603 => EcdsaSecp521r1Sha512,
        0x0804 => RsaPssRsaeSha256,
        0x0805 => RsaPssRsaeSha384,
        0x0806 => RsaPssRsaeSha512,
        0x0401 => RsaPkcs1Sha256,
        0x0501 => RsaPkcs1Sha384,
        0x0601 => RsaPkcs1Sha512,
        0x0203 => EcdsaSha1,
        0x0201 => RsaPkcs1Sha1,
        _ => return Err(error(Kind::UnsupportedSetting, "tls.signature_schemes")),
    })
}

pub(in crate::fingerprint) fn extension(id: u16) -> Result<ClientHelloExtension> {
    use ClientHelloExtension::*;
    Ok(match id {
        0 => ServerName,
        23 => ExtendedMasterSecret,
        65281 => RenegotiationInfo,
        10 => SupportedGroups,
        11 => EcPointFormats,
        35 => SessionTicket,
        28 => RecordSizeLimit,
        16 => Alpn,
        5 => StatusRequest,
        18 => SignedCertificateTimestamp,
        51 => KeyShare,
        43 => SupportedVersions,
        13 => SignatureAlgorithms,
        34 => DelegatedCredential,
        45 => PskKeyExchangeModes,
        27 => CertificateCompression,
        0xca34 => TrustAnchors,
        17613 => ApplicationSettings,
        17513 => ApplicationSettingsLegacy,
        0xfe0d => EncryptedClientHello,
        _ => return Err(error(Kind::UnsupportedSetting, "tls.extension_order")),
    })
}
