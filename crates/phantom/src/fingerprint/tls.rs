//! Complete TLS description parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{
    AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtension,
    ClientHelloExtensionOrder, EchGreaseAead, EchGreasePayloadLength, EchGreaseSettings,
    EchSettings, NamedGroup, SessionTicketOrder, SessionTickets, SignatureScheme, TlsSettings,
    TlsVersion, TlsVersionRange, TrustAnchorIds, TrustAnchorOrder, TrustAnchorOrders,
};

pub(super) fn parse(v: &Value) -> Result<TlsSettings> {
    v.record(
        &[
            "versions",
            "cipher_suites",
            "groups",
            "key_shares",
            "signature_schemes",
            "delegated_credential_schemes",
            "alpn_protocols",
            "alps",
            "certificate_compression",
            "session_tickets",
            "session_ticket_order",
            "session_ticket_extension_when_resuming",
            "tcp_early_data",
            "record_size_limit",
            "tls12_extensions_in_tls13_client_hello",
            "requested_trust_anchor_ids",
            "grease",
            "grease_signature_algorithms",
            "extension_order",
            "ech",
            "request_ocsp_staple",
            "request_signed_certificate_timestamps",
            "aes_hardware",
            "close_notify",
        ],
        "tls",
    )?;
    let settings = TlsSettings {
        versions: versions(v.member("versions", "tls.versions")?)?,
        cipher_suites: v
            .member("cipher_suites", "tls.cipher_suites")?
            .list("tls.cipher_suites", cipher_suites)?,
        groups: v
            .member("groups", "tls.groups")?
            .list("tls.groups", groups)?,
        key_shares: v
            .member("key_shares", "tls.key_shares")?
            .list("tls.key_shares", key_shares)?,
        signature_schemes: v
            .member("signature_schemes", "tls.signature_schemes")?
            .list("tls.signature_schemes", signature_schemes)?,
        delegated_credential_schemes: v
            .member(
                "delegated_credential_schemes",
                "tls.delegated_credential_schemes",
            )?
            .list(
                "tls.delegated_credential_schemes",
                delegated_credential_schemes,
            )?,
        alpn_protocols: v
            .member("alpn_protocols", "tls.alpn_protocols")?
            .list("tls.alpn_protocols", |v| v.bytes("tls.alpn_protocols"))?,
        alps: v.member("alps", "tls.alps")?.optional(alps)?,
        certificate_compression: v
            .member("certificate_compression", "tls.certificate_compression")?
            .list("tls.certificate_compression", certificate_compression)?,
        session_tickets: session_tickets(v.member("session_tickets", "tls.session_tickets")?)?,
        session_ticket_order: session_ticket_order(
            v.member("session_ticket_order", "tls.session_ticket_order")?,
        )?,
        session_ticket_extension_when_resuming: v
            .member(
                "session_ticket_extension_when_resuming",
                "tls.session_ticket_extension_when_resuming",
            )?
            .boolean("tls.session_ticket_extension_when_resuming")?,
        tcp_early_data: v
            .member("tcp_early_data", "tls.tcp_early_data")?
            .boolean("tls.tcp_early_data")?,
        record_size_limit: v
            .member("record_size_limit", "tls.record_size_limit")?
            .optional(|v| v.integer("tls.record_size_limit"))?,
        tls12_extensions_in_tls13_client_hello: v
            .member(
                "tls12_extensions_in_tls13_client_hello",
                "tls.tls12_extensions_in_tls13_client_hello",
            )?
            .boolean("tls.tls12_extensions_in_tls13_client_hello")?,
        requested_trust_anchor_ids: v
            .member(
                "requested_trust_anchor_ids",
                "tls.requested_trust_anchor_ids",
            )?
            .optional(anchors)?,
        grease: v.member("grease", "tls.grease")?.boolean("tls.grease")?,
        grease_signature_algorithms: v
            .member(
                "grease_signature_algorithms",
                "tls.grease_signature_algorithms",
            )?
            .boolean("tls.grease_signature_algorithms")?,
        extension_order: extension_order(v.member("extension_order", "tls.extension_order")?)?,
        ech: ech(v.member("ech", "tls.ech")?)?,
        request_ocsp_staple: v
            .member("request_ocsp_staple", "tls.request_ocsp_staple")?
            .boolean("tls.request_ocsp_staple")?,
        request_signed_certificate_timestamps: v
            .member(
                "request_signed_certificate_timestamps",
                "tls.request_signed_certificate_timestamps",
            )?
            .boolean("tls.request_signed_certificate_timestamps")?,
        aes_hardware: v
            .member("aes_hardware", "tls.aes_hardware")?
            .boolean("tls.aes_hardware")?,
        close_notify: v
            .member("close_notify", "tls.close_notify")?
            .boolean("tls.close_notify")?,
    };
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("tls", error))?;
    Ok(settings)
}

fn cipher_suites(v: &Value) -> Result<CipherSuite> {
    match v.text("tls.cipher_suites")? {
        "Aes128GcmSha256" => Ok(CipherSuite::Aes128GcmSha256),
        "Aes256GcmSha384" => Ok(CipherSuite::Aes256GcmSha384),
        "Chacha20Poly1305Sha256" => Ok(CipherSuite::Chacha20Poly1305Sha256),
        "EcdheEcdsaAes128GcmSha256" => Ok(CipherSuite::EcdheEcdsaAes128GcmSha256),
        "EcdheRsaAes128GcmSha256" => Ok(CipherSuite::EcdheRsaAes128GcmSha256),
        "EcdheEcdsaAes256GcmSha384" => Ok(CipherSuite::EcdheEcdsaAes256GcmSha384),
        "EcdheRsaAes256GcmSha384" => Ok(CipherSuite::EcdheRsaAes256GcmSha384),
        "EcdheEcdsaChacha20Poly1305Sha256" => Ok(CipherSuite::EcdheEcdsaChacha20Poly1305Sha256),
        "EcdheRsaChacha20Poly1305Sha256" => Ok(CipherSuite::EcdheRsaChacha20Poly1305Sha256),
        "EcdheRsaAes128CbcSha" => Ok(CipherSuite::EcdheRsaAes128CbcSha),
        "EcdheRsaAes256CbcSha" => Ok(CipherSuite::EcdheRsaAes256CbcSha),
        "EcdheEcdsaAes128CbcSha" => Ok(CipherSuite::EcdheEcdsaAes128CbcSha),
        "EcdheEcdsaAes256CbcSha" => Ok(CipherSuite::EcdheEcdsaAes256CbcSha),
        "EcdheEcdsa3DesEdeCbcSha" => Ok(CipherSuite::EcdheEcdsa3DesEdeCbcSha),
        "EcdheRsa3DesEdeCbcSha" => Ok(CipherSuite::EcdheRsa3DesEdeCbcSha),
        "RsaAes128GcmSha256" => Ok(CipherSuite::RsaAes128GcmSha256),
        "RsaAes256GcmSha384" => Ok(CipherSuite::RsaAes256GcmSha384),
        "RsaAes128CbcSha" => Ok(CipherSuite::RsaAes128CbcSha),
        "RsaAes256CbcSha" => Ok(CipherSuite::RsaAes256CbcSha),
        "Rsa3DesEdeCbcSha" => Ok(CipherSuite::Rsa3DesEdeCbcSha),
        _ => Err(json::unsupported("tls.cipher_suites")),
    }
}

fn groups(v: &Value) -> Result<NamedGroup> {
    match v.text("tls.groups")? {
        "X25519MlKem768" => Ok(NamedGroup::X25519MlKem768),
        "X25519" => Ok(NamedGroup::X25519),
        "Secp256r1" => Ok(NamedGroup::Secp256r1),
        "Secp384r1" => Ok(NamedGroup::Secp384r1),
        "Secp521r1" => Ok(NamedGroup::Secp521r1),
        "Ffdhe2048" => Ok(NamedGroup::Ffdhe2048),
        "Ffdhe3072" => Ok(NamedGroup::Ffdhe3072),
        _ => Err(json::unsupported("tls.groups")),
    }
}

fn signature_schemes(v: &Value) -> Result<SignatureScheme> {
    match v.text("tls.signature_schemes")? {
        "MlDsa44" => Ok(SignatureScheme::MlDsa44),
        "MlDsa65" => Ok(SignatureScheme::MlDsa65),
        "MlDsa87" => Ok(SignatureScheme::MlDsa87),
        "EcdsaSecp256r1Sha256" => Ok(SignatureScheme::EcdsaSecp256r1Sha256),
        "RsaPssRsaeSha256" => Ok(SignatureScheme::RsaPssRsaeSha256),
        "RsaPkcs1Sha256" => Ok(SignatureScheme::RsaPkcs1Sha256),
        "EcdsaSecp384r1Sha384" => Ok(SignatureScheme::EcdsaSecp384r1Sha384),
        "EcdsaSecp521r1Sha512" => Ok(SignatureScheme::EcdsaSecp521r1Sha512),
        "RsaPssRsaeSha384" => Ok(SignatureScheme::RsaPssRsaeSha384),
        "RsaPkcs1Sha384" => Ok(SignatureScheme::RsaPkcs1Sha384),
        "RsaPssRsaeSha512" => Ok(SignatureScheme::RsaPssRsaeSha512),
        "RsaPkcs1Sha512" => Ok(SignatureScheme::RsaPkcs1Sha512),
        "EcdsaSha1" => Ok(SignatureScheme::EcdsaSha1),
        "RsaPkcs1Sha1" => Ok(SignatureScheme::RsaPkcs1Sha1),
        _ => Err(json::unsupported("tls.signature_schemes")),
    }
}

fn certificate_compression(v: &Value) -> Result<CertificateCompression> {
    match v.text("tls.certificate_compression")? {
        "Zlib" => Ok(CertificateCompression::Zlib),
        "Brotli" => Ok(CertificateCompression::Brotli),
        "Zstd" => Ok(CertificateCompression::Zstd),
        _ => Err(json::unsupported("tls.certificate_compression")),
    }
}

fn key_shares(v: &Value) -> Result<NamedGroup> {
    match v.text("tls.key_shares")? {
        "X25519MlKem768" => Ok(NamedGroup::X25519MlKem768),
        "X25519" => Ok(NamedGroup::X25519),
        "Secp256r1" => Ok(NamedGroup::Secp256r1),
        "Secp384r1" => Ok(NamedGroup::Secp384r1),
        "Secp521r1" => Ok(NamedGroup::Secp521r1),
        "Ffdhe2048" => Ok(NamedGroup::Ffdhe2048),
        "Ffdhe3072" => Ok(NamedGroup::Ffdhe3072),
        _ => Err(json::unsupported("tls.key_shares")),
    }
}

fn delegated_credential_schemes(v: &Value) -> Result<SignatureScheme> {
    match v.text("tls.delegated_credential_schemes")? {
        "MlDsa44" => Ok(SignatureScheme::MlDsa44),
        "MlDsa65" => Ok(SignatureScheme::MlDsa65),
        "MlDsa87" => Ok(SignatureScheme::MlDsa87),
        "EcdsaSecp256r1Sha256" => Ok(SignatureScheme::EcdsaSecp256r1Sha256),
        "RsaPssRsaeSha256" => Ok(SignatureScheme::RsaPssRsaeSha256),
        "RsaPkcs1Sha256" => Ok(SignatureScheme::RsaPkcs1Sha256),
        "EcdsaSecp384r1Sha384" => Ok(SignatureScheme::EcdsaSecp384r1Sha384),
        "EcdsaSecp521r1Sha512" => Ok(SignatureScheme::EcdsaSecp521r1Sha512),
        "RsaPssRsaeSha384" => Ok(SignatureScheme::RsaPssRsaeSha384),
        "RsaPkcs1Sha384" => Ok(SignatureScheme::RsaPkcs1Sha384),
        "RsaPssRsaeSha512" => Ok(SignatureScheme::RsaPssRsaeSha512),
        "RsaPkcs1Sha512" => Ok(SignatureScheme::RsaPkcs1Sha512),
        "EcdsaSha1" => Ok(SignatureScheme::EcdsaSha1),
        "RsaPkcs1Sha1" => Ok(SignatureScheme::RsaPkcs1Sha1),
        _ => Err(json::unsupported("tls.delegated_credential_schemes")),
    }
}

fn version(v: &Value) -> Result<TlsVersion> {
    match v.text("tls.versions")? {
        "Tls10" => Ok(TlsVersion::Tls10),
        "Tls11" => Ok(TlsVersion::Tls11),
        "Tls12" => Ok(TlsVersion::Tls12),
        "Tls13" => Ok(TlsVersion::Tls13),
        _ => Err(json::unsupported("tls.versions")),
    }
}

fn session_ticket_order(v: &Value) -> Result<SessionTicketOrder> {
    match v.text("tls.session_ticket_order")? {
        "NewestFirst" => Ok(SessionTicketOrder::NewestFirst),
        "OldestConnectionFirst" => Ok(SessionTicketOrder::OldestConnectionFirst),
        "OldestFirst" => Ok(SessionTicketOrder::OldestFirst),
        _ => Err(json::unsupported("tls.session_ticket_order")),
    }
}

fn extension(v: &Value) -> Result<ClientHelloExtension> {
    match v.text("tls.extension_order.extensions")? {
        "ServerName" => Ok(ClientHelloExtension::ServerName),
        "ExtendedMasterSecret" => Ok(ClientHelloExtension::ExtendedMasterSecret),
        "RenegotiationInfo" => Ok(ClientHelloExtension::RenegotiationInfo),
        "SupportedGroups" => Ok(ClientHelloExtension::SupportedGroups),
        "EcPointFormats" => Ok(ClientHelloExtension::EcPointFormats),
        "SessionTicket" => Ok(ClientHelloExtension::SessionTicket),
        "RecordSizeLimit" => Ok(ClientHelloExtension::RecordSizeLimit),
        "Alpn" => Ok(ClientHelloExtension::Alpn),
        "StatusRequest" => Ok(ClientHelloExtension::StatusRequest),
        "SignedCertificateTimestamp" => Ok(ClientHelloExtension::SignedCertificateTimestamp),
        "KeyShare" => Ok(ClientHelloExtension::KeyShare),
        "EarlyData" => Ok(ClientHelloExtension::EarlyData),
        "SupportedVersions" => Ok(ClientHelloExtension::SupportedVersions),
        "SignatureAlgorithms" => Ok(ClientHelloExtension::SignatureAlgorithms),
        "DelegatedCredential" => Ok(ClientHelloExtension::DelegatedCredential),
        "PskKeyExchangeModes" => Ok(ClientHelloExtension::PskKeyExchangeModes),
        "CertificateCompression" => Ok(ClientHelloExtension::CertificateCompression),
        "TrustAnchors" => Ok(ClientHelloExtension::TrustAnchors),
        "ApplicationSettings" => Ok(ClientHelloExtension::ApplicationSettings),
        "ApplicationSettingsLegacy" => Ok(ClientHelloExtension::ApplicationSettingsLegacy),
        "EncryptedClientHello" => Ok(ClientHelloExtension::EncryptedClientHello),
        "QuicTransportParameters" => Ok(ClientHelloExtension::QuicTransportParameters),
        _ => Err(json::unsupported("tls.extension_order.extensions")),
    }
}

fn aead(v: &Value) -> Result<EchGreaseAead> {
    match v.text("tls.ech.settings.aeads")? {
        "Aes128Gcm" => Ok(EchGreaseAead::Aes128Gcm),
        "Aes256Gcm" => Ok(EchGreaseAead::Aes256Gcm),
        "ChaCha20Poly1305" => Ok(EchGreaseAead::ChaCha20Poly1305),
        _ => Err(json::unsupported("tls.ech.settings.aeads")),
    }
}

fn versions(v: &Value) -> Result<TlsVersionRange> {
    v.record(&["min", "max"], "tls.versions")?;
    TlsVersionRange::new(
        version(v.member("min", "tls.versions.min")?)?,
        version(v.member("max", "tls.versions.max")?)?,
    )
    .map_err(|error| FingerprintImportError::native("tls.versions", error))
}
fn session_tickets(v: &Value) -> Result<SessionTickets> {
    v.record(&["enabled", "tcp_per_origin"], "tls.session_tickets")?;
    let limit = v.member("tcp_per_origin", "tls.session_tickets.tcp_per_origin")?;
    if v.member("enabled", "tls.session_tickets.enabled")?
        .boolean("tls.session_tickets.enabled")?
    {
        SessionTickets::enabled(limit.integer("tls.session_tickets.tcp_per_origin")?)
            .map_err(|error| FingerprintImportError::native("tls.session_tickets", error))
    } else {
        limit.null("tls.session_tickets.tcp_per_origin")?;
        Ok(SessionTickets::disabled())
    }
}
fn anchors(v: &Value) -> Result<TrustAnchorIds> {
    v.record(&["kind", "orders"], "tls.requested_trust_anchor_ids")?;
    let orders = v
        .member("orders", "tls.requested_trust_anchor_ids.orders")?
        .list("tls.requested_trust_anchor_ids.orders", |v| {
            TrustAnchorOrder::new(v.list("tls.requested_trust_anchor_ids.orders", |v| {
                v.bytes("tls.requested_trust_anchor_ids.orders")
            })?)
            .map_err(|error| {
                FingerprintImportError::native("tls.requested_trust_anchor_ids", error)
            })
        })?;
    match v
        .member("kind", "tls.requested_trust_anchor_ids.kind")?
        .text("tls.requested_trust_anchor_ids.kind")?
    {
        "Fixed" => {
            let mut orders = orders.into_iter();
            let Some(order) = orders.next() else {
                return Err(json::invalid("tls.requested_trust_anchor_ids.orders"));
            };
            if orders.next().is_some() {
                return Err(json::invalid("tls.requested_trust_anchor_ids.orders"));
            }
            Ok(TrustAnchorIds::Fixed(order))
        }
        "PerClient" => Ok(TrustAnchorIds::PerClient(
            TrustAnchorOrders::new(orders).map_err(|error| {
                FingerprintImportError::native("tls.requested_trust_anchor_ids", error)
            })?,
        )),
        "PerConnection" => Ok(TrustAnchorIds::PerConnection(
            TrustAnchorOrders::new(orders).map_err(|error| {
                FingerprintImportError::native("tls.requested_trust_anchor_ids", error)
            })?,
        )),
        _ => Err(json::unsupported("tls.requested_trust_anchor_ids.kind")),
    }
}
fn extension_order(v: &Value) -> Result<ClientHelloExtensionOrder> {
    v.record(&["kind", "extensions"], "tls.extension_order")?;
    let extensions = v
        .member("extensions", "tls.extension_order.extensions")?
        .list("tls.extension_order.extensions", extension)?;
    match v
        .member("kind", "tls.extension_order.kind")?
        .text("tls.extension_order.kind")?
    {
        "Fixed" => Ok(ClientHelloExtensionOrder::Fixed(extensions)),
        "PermutedWithTail" => Ok(ClientHelloExtensionOrder::PermutedWithTail(extensions)),
        "BackendDefault" if extensions.is_empty() => Ok(ClientHelloExtensionOrder::BackendDefault),
        "Permuted" if extensions.is_empty() => Ok(ClientHelloExtensionOrder::Permuted),
        "BackendDefault" | "Permuted" => Err(json::invalid("tls.extension_order.extensions")),
        _ => Err(json::unsupported("tls.extension_order.kind")),
    }
}
fn ech(v: &Value) -> Result<EchSettings> {
    v.record(&["kind", "settings"], "tls.ech")?;
    let settings = v.member("settings", "tls.ech.settings")?;
    match v.member("kind", "tls.ech.kind")?.text("tls.ech.kind")? {
        "Disabled" => {
            settings.null("tls.ech.settings")?;
            Ok(EchSettings::Disabled)
        }
        "Grease" => Ok(EchSettings::Grease(ech_grease(settings)?)),
        "HttpsRecords" => Ok(EchSettings::HttpsRecords(ech_grease(settings)?)),
        _ => Err(json::unsupported("tls.ech.kind")),
    }
}
fn ech_grease(v: &Value) -> Result<EchGreaseSettings> {
    v.record(&["payload_length", "aeads"], "tls.ech.settings")?;
    let payload = v.member("payload_length", "tls.ech.settings.payload_length")?;
    payload.record(&["kind", "value"], "tls.ech.settings.payload_length")?;
    let value = payload.member("value", "tls.ech.settings.payload_length.value")?;
    let length = match payload
        .member("kind", "tls.ech.settings.payload_length.kind")?
        .text("tls.ech.settings.payload_length.kind")?
    {
        "BackendDefault" => {
            value.null("tls.ech.settings.payload_length.value")?;
            EchGreasePayloadLength::BackendDefault
        }
        "Exact" => {
            EchGreasePayloadLength::Exact(value.integer("tls.ech.settings.payload_length.value")?)
        }
        "FromClientHello" => EchGreasePayloadLength::FromClientHello {
            maximum_name_length: value.integer("tls.ech.settings.payload_length.value")?,
        },
        _ => return Err(json::unsupported("tls.ech.settings.payload_length.kind")),
    };
    EchGreaseSettings::new(
        length,
        v.member("aeads", "tls.ech.settings.aeads")?
            .list("tls.ech.settings.aeads", aead)?,
    )
    .map_err(|error| FingerprintImportError::native("tls.ech.settings", error))
}
pub(super) fn alps(v: &Value) -> Result<AlpsSettings> {
    v.record(&["protocol", "settings", "use_new_codepoint"], "tls.alps")?;
    let settings = AlpsSettings {
        protocol: v
            .member("protocol", "tls.alps.protocol")?
            .bytes("tls.alps.protocol")?,
        settings: v
            .member("settings", "tls.alps.settings")?
            .bytes("tls.alps.settings")?,
        use_new_codepoint: v
            .member("use_new_codepoint", "tls.alps.use_new_codepoint")?
            .boolean("tls.alps.use_new_codepoint")?,
    };
    Ok(settings)
}
