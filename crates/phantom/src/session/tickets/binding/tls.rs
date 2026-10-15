use phantom_profile::{
    CertificateCompression, CipherSuite, ClientHelloExtension, EchGreaseAead, NamedGroup,
    SessionTicketOrder, SignatureScheme, TlsVersion,
};

use super::{PreparationError, encoding::Encoder};

fn tls_version(e: &mut Encoder, value: &TlsVersion) -> Result<(), PreparationError> {
    e.u8(match value {
        TlsVersion::Tls10 => 0,
        TlsVersion::Tls11 => 1,
        TlsVersion::Tls12 => 2,
        TlsVersion::Tls13 => 3,
        _ => return Err(PreparationError::Unsupported("TlsVersion")),
    })
}

fn cipher_suite(e: &mut Encoder, value: &CipherSuite) -> Result<(), PreparationError> {
    e.u8(match value {
        CipherSuite::Aes128GcmSha256 => 0,
        CipherSuite::Aes256GcmSha384 => 1,
        CipherSuite::Chacha20Poly1305Sha256 => 2,
        CipherSuite::EcdheEcdsaAes128GcmSha256 => 3,
        CipherSuite::EcdheRsaAes128GcmSha256 => 4,
        CipherSuite::EcdheEcdsaAes256GcmSha384 => 5,
        CipherSuite::EcdheRsaAes256GcmSha384 => 6,
        CipherSuite::EcdheEcdsaChacha20Poly1305Sha256 => 7,
        CipherSuite::EcdheRsaChacha20Poly1305Sha256 => 8,
        CipherSuite::EcdheRsaAes128CbcSha => 9,
        CipherSuite::EcdheRsaAes256CbcSha => 10,
        CipherSuite::EcdheEcdsaAes128CbcSha => 11,
        CipherSuite::EcdheEcdsaAes256CbcSha => 12,
        CipherSuite::EcdheEcdsa3DesEdeCbcSha => 13,
        CipherSuite::EcdheRsa3DesEdeCbcSha => 14,
        CipherSuite::RsaAes128GcmSha256 => 15,
        CipherSuite::RsaAes256GcmSha384 => 16,
        CipherSuite::RsaAes128CbcSha => 17,
        CipherSuite::RsaAes256CbcSha => 18,
        CipherSuite::Rsa3DesEdeCbcSha => 19,
        _ => return Err(PreparationError::Unsupported("CipherSuite")),
    })
}

fn named_group(e: &mut Encoder, value: &NamedGroup) -> Result<(), PreparationError> {
    e.u8(match value {
        NamedGroup::X25519MlKem768 => 0,
        NamedGroup::X25519 => 1,
        NamedGroup::Secp256r1 => 2,
        NamedGroup::Secp384r1 => 3,
        NamedGroup::Secp521r1 => 4,
        NamedGroup::Ffdhe2048 => 5,
        NamedGroup::Ffdhe3072 => 6,
        _ => return Err(PreparationError::Unsupported("NamedGroup")),
    })
}

fn signature_scheme(e: &mut Encoder, value: &SignatureScheme) -> Result<(), PreparationError> {
    e.u8(match value {
        SignatureScheme::MlDsa44 => 0,
        SignatureScheme::MlDsa65 => 1,
        SignatureScheme::MlDsa87 => 2,
        SignatureScheme::EcdsaSecp256r1Sha256 => 3,
        SignatureScheme::RsaPssRsaeSha256 => 4,
        SignatureScheme::RsaPkcs1Sha256 => 5,
        SignatureScheme::EcdsaSecp384r1Sha384 => 6,
        SignatureScheme::EcdsaSecp521r1Sha512 => 7,
        SignatureScheme::RsaPssRsaeSha384 => 8,
        SignatureScheme::RsaPkcs1Sha384 => 9,
        SignatureScheme::RsaPssRsaeSha512 => 10,
        SignatureScheme::RsaPkcs1Sha512 => 11,
        SignatureScheme::EcdsaSha1 => 12,
        SignatureScheme::RsaPkcs1Sha1 => 13,
        _ => return Err(PreparationError::Unsupported("SignatureScheme")),
    })
}

fn certificate_compression_kind(
    e: &mut Encoder,
    value: &CertificateCompression,
) -> Result<(), PreparationError> {
    e.u8(match value {
        CertificateCompression::Zlib => 0,
        CertificateCompression::Brotli => 1,
        CertificateCompression::Zstd => 2,
        _ => return Err(PreparationError::Unsupported("CertificateCompression")),
    })
}

fn client_hello_extension(
    e: &mut Encoder,
    value: &ClientHelloExtension,
) -> Result<(), PreparationError> {
    e.u8(match value {
        ClientHelloExtension::ServerName => 0,
        ClientHelloExtension::ExtendedMasterSecret => 1,
        ClientHelloExtension::RenegotiationInfo => 2,
        ClientHelloExtension::SupportedGroups => 3,
        ClientHelloExtension::EcPointFormats => 4,
        ClientHelloExtension::SessionTicket => 5,
        ClientHelloExtension::RecordSizeLimit => 6,
        ClientHelloExtension::Alpn => 7,
        ClientHelloExtension::StatusRequest => 8,
        ClientHelloExtension::SignedCertificateTimestamp => 9,
        ClientHelloExtension::KeyShare => 10,
        ClientHelloExtension::EarlyData => 11,
        ClientHelloExtension::SupportedVersions => 12,
        ClientHelloExtension::SignatureAlgorithms => 13,
        ClientHelloExtension::DelegatedCredential => 14,
        ClientHelloExtension::PskKeyExchangeModes => 15,
        ClientHelloExtension::CertificateCompression => 16,
        ClientHelloExtension::TrustAnchors => 17,
        ClientHelloExtension::ApplicationSettings => 18,
        ClientHelloExtension::ApplicationSettingsLegacy => 19,
        ClientHelloExtension::EncryptedClientHello => 20,
        ClientHelloExtension::QuicTransportParameters => 21,
        _ => return Err(PreparationError::Unsupported("ClientHelloExtension")),
    })
}

fn session_ticket_order_kind(
    e: &mut Encoder,
    value: &SessionTicketOrder,
) -> Result<(), PreparationError> {
    e.u8(match value {
        SessionTicketOrder::NewestFirst => 0,
        SessionTicketOrder::OldestConnectionFirst => 1,
        SessionTicketOrder::OldestFirst => 2,
        _ => return Err(PreparationError::Unsupported("SessionTicketOrder")),
    })
}

fn ech_grease_aead(e: &mut Encoder, value: &EchGreaseAead) -> Result<(), PreparationError> {
    e.u8(match value {
        EchGreaseAead::Aes128Gcm => 0,
        EchGreaseAead::Aes256Gcm => 1,
        EchGreaseAead::ChaCha20Poly1305 => 2,
        _ => return Err(PreparationError::Unsupported("EchGreaseAead")),
    })
}
use phantom_profile::{
    AlpsSettings, ClientHelloExtensionOrder, EchGreasePayloadLength, EchGreaseSettings,
    EchSettings, TlsSettings, TrustAnchorIds, TrustAnchorOrder,
};

pub(super) fn encode(
    e: &mut Encoder,
    value: &TlsSettings,
    anchors: Option<&TrustAnchorIds>,
) -> Result<(), PreparationError> {
    let TlsSettings {
        versions,
        cipher_suites,
        groups,
        key_shares,
        signature_schemes,
        delegated_credential_schemes,
        alpn_protocols,
        alps,
        certificate_compression,
        session_tickets,
        session_ticket_order,
        session_ticket_extension_when_resuming,
        tcp_early_data,
        record_size_limit,
        tls12_extensions_in_tls13_client_hello,
        requested_trust_anchor_ids,
        grease,
        grease_signature_algorithms,
        extension_order,
        ech,
        request_ocsp_staple,
        request_signed_certificate_timestamps,
        aes_hardware,
        close_notify,
    } = value;
    tls_version(e, &versions.min())?;
    tls_version(e, &versions.max())?;
    e.list(cipher_suites, cipher_suite)?;
    e.list(groups, named_group)?;
    e.list(key_shares, named_group)?;
    e.list(signature_schemes, signature_scheme)?;
    e.list(delegated_credential_schemes, signature_scheme)?;
    e.list(alpn_protocols, |e, value| e.bytes(value))?;
    e.option(alps.as_ref(), |e, value| {
        let AlpsSettings {
            protocol,
            settings,
            use_new_codepoint,
        } = value;
        e.bytes(protocol)?;
        e.bytes(settings)?;
        e.bool(*use_new_codepoint)
    })?;
    e.list(certificate_compression, certificate_compression_kind)?;
    e.bool(session_tickets.is_enabled())?;
    e.option(
        session_tickets.tcp_per_origin_limit().as_ref(),
        |e, limit| e.u8(limit.get()),
    )?;
    session_ticket_order_kind(e, session_ticket_order)?;
    e.bool(*session_ticket_extension_when_resuming)?;
    e.bool(*tcp_early_data)?;
    e.option(record_size_limit.as_ref(), |e, value| e.u16(*value))?;
    e.bool(*tls12_extensions_in_tls13_client_hello)?;
    e.option(
        anchors.or(requested_trust_anchor_ids.as_ref()),
        encode_anchors,
    )?;
    e.bool(*grease)?;
    e.bool(*grease_signature_algorithms)?;
    match extension_order {
        ClientHelloExtensionOrder::BackendDefault => e.u8(0)?,
        ClientHelloExtensionOrder::Permuted => e.u8(1)?,
        ClientHelloExtensionOrder::Fixed(values) => {
            e.u8(2)?;
            e.list(values, client_hello_extension)?;
        }
        ClientHelloExtensionOrder::PermutedWithTail(values) => {
            e.u8(3)?;
            e.list(values, client_hello_extension)?;
        }
        _ => return Err(PreparationError::Unsupported("extension_order")),
    }
    match ech {
        EchSettings::Disabled => e.u8(0)?,
        EchSettings::Grease(settings) => {
            e.u8(1)?;
            encode_ech(e, settings)?;
        }
        EchSettings::HttpsRecords(settings) => {
            e.u8(2)?;
            encode_ech(e, settings)?;
        }
        _ => return Err(PreparationError::Unsupported("ech")),
    }
    e.bool(*request_ocsp_staple)?;
    e.bool(*request_signed_certificate_timestamps)?;
    e.bool(*aes_hardware)?;
    e.bool(*close_notify)
}

fn encode_ech(e: &mut Encoder, value: &EchGreaseSettings) -> Result<(), PreparationError> {
    match value.payload_length() {
        EchGreasePayloadLength::BackendDefault => e.u8(0)?,
        EchGreasePayloadLength::Exact(length) => {
            e.u8(1)?;
            e.u16(length)?;
        }
        EchGreasePayloadLength::FromClientHello {
            maximum_name_length,
        } => {
            e.u8(2)?;
            e.u8(maximum_name_length)?;
        }
        _ => return Err(PreparationError::Unsupported("ech_payload_length")),
    }
    e.list(value.aeads(), ech_grease_aead)
}

fn encode_order(e: &mut Encoder, value: &TrustAnchorOrder) -> Result<(), PreparationError> {
    e.list(value.as_slice(), |e, id| e.bytes(id))
}

fn encode_anchors(e: &mut Encoder, value: &TrustAnchorIds) -> Result<(), PreparationError> {
    match value {
        TrustAnchorIds::Fixed(order) => {
            e.u8(0)?;
            encode_order(e, order)
        }
        TrustAnchorIds::PerClient(orders) => {
            e.u8(1)?;
            e.list(orders.as_slice(), encode_order)
        }
        TrustAnchorIds::PerConnection(orders) => {
            e.u8(2)?;
            e.list(orders.as_slice(), encode_order)
        }
        _ => Err(PreparationError::Unsupported("trust_anchor_ids")),
    }
}

pub(super) fn witness(
    policy: Option<&TrustAnchorIds>,
    sampled: Option<&TrustAnchorIds>,
) -> Result<Option<Vec<u8>>, PreparationError> {
    let Some(TrustAnchorIds::PerClient(candidates)) = policy else {
        return Ok(None);
    };
    let Some(TrustAnchorIds::Fixed(order)) = sampled else {
        return Err(PreparationError::DrawMismatch);
    };
    if !candidates.as_slice().contains(order) {
        return Err(PreparationError::DrawMismatch);
    }
    let mut e = Encoder::new();
    encode_order(&mut e, order)?;
    Ok(Some(e.finish()))
}

/// Reads only the existing TCP/QUIC draw frames, never a full profile.
pub(super) fn validate_source_witness(
    tcp: Option<&TrustAnchorIds>,
    quic: Option<&TrustAnchorIds>,
    witness: &[u8],
) -> Result<(), PreparationError> {
    if witness.len() > super::encoding::MAX_POLICY_BYTES {
        return Err(PreparationError::TooLarge);
    }
    let mut remaining = witness;
    for policy in [tcp, quic] {
        let source = take_draw_witness(&mut remaining).ok_or(PreparationError::DrawMismatch)?;
        match (policy, source) {
            (None, None) => {}
            (Some(TrustAnchorIds::PerClient(candidates)), Some(source))
                if candidates
                    .as_slice()
                    .iter()
                    .any(|order| witness_matches_order(source, order)) => {}
            _ => return Err(PreparationError::DrawMismatch),
        }
    }
    if !remaining.is_empty() {
        return Err(PreparationError::DrawMismatch);
    }
    Ok(())
}

fn take_draw_witness<'a>(input: &mut &'a [u8]) -> Option<Option<&'a [u8]>> {
    let (tag, rest) = (*input).split_first()?;
    *input = rest;
    match *tag {
        0 => Some(None),
        1 => {
            let length = usize::try_from(take_u32(input)?).ok()?;
            let value = (*input).get(..length)?;
            *input = (*input).get(length..)?;
            Some(Some(value))
        }
        _ => None,
    }
}

fn take_u32(input: &mut &[u8]) -> Option<u32> {
    let value = u32::from_be_bytes(input.get(..4)?.try_into().ok()?);
    *input = input.get(4..)?;
    Some(value)
}

fn witness_matches_order(mut witness: &[u8], order: &TrustAnchorOrder) -> bool {
    let Some(count) = take_u32(&mut witness).and_then(|n| usize::try_from(n).ok()) else {
        return false;
    };
    if count != order.as_slice().len() {
        return false;
    }
    for id in order.as_slice() {
        let Some(length) = take_u32(&mut witness).and_then(|n| usize::try_from(n).ok()) else {
            return false;
        };
        if witness.get(..length) != Some(id.as_ref()) {
            return false;
        }
        let Some(rest) = witness.get(length..) else {
            return false;
        };
        witness = rest;
    }
    witness.is_empty()
}
