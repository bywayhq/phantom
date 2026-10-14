"""Closed TLS policies and generated native literal assertions."""

from .declarations import (
    DeclarationError,
    boolean,
    bounded_integer,
    bounded_list,
    choice,
    keys,
    validate_bytes,
)
from .rust_literals import (
    rust_bytes,
    rust_option,
)

TLS_VERSIONS = ("Tls10", "Tls11", "Tls12", "Tls13")


TLS_ENUM_LISTS = {
    "cipher_suites": (
        "CipherSuite",
        (
            "Aes128GcmSha256",
            "Aes256GcmSha384",
            "Chacha20Poly1305Sha256",
            "EcdheEcdsaAes128GcmSha256",
            "EcdheRsaAes128GcmSha256",
            "EcdheEcdsaAes256GcmSha384",
            "EcdheRsaAes256GcmSha384",
            "EcdheEcdsaChacha20Poly1305Sha256",
            "EcdheRsaChacha20Poly1305Sha256",
            "EcdheRsaAes128CbcSha",
            "EcdheRsaAes256CbcSha",
            "EcdheEcdsaAes128CbcSha",
            "EcdheEcdsaAes256CbcSha",
            "EcdheEcdsa3DesEdeCbcSha",
            "EcdheRsa3DesEdeCbcSha",
            "RsaAes128GcmSha256",
            "RsaAes256GcmSha384",
            "RsaAes128CbcSha",
            "RsaAes256CbcSha",
            "Rsa3DesEdeCbcSha",
        ),
    ),
    "groups": (
        "NamedGroup",
        (
            "X25519MlKem768",
            "X25519",
            "Secp256r1",
            "Secp384r1",
            "Secp521r1",
            "Ffdhe2048",
            "Ffdhe3072",
        ),
    ),
    "signature_schemes": (
        "SignatureScheme",
        (
            "MlDsa44",
            "MlDsa65",
            "MlDsa87",
            "EcdsaSecp256r1Sha256",
            "RsaPssRsaeSha256",
            "RsaPkcs1Sha256",
            "EcdsaSecp384r1Sha384",
            "EcdsaSecp521r1Sha512",
            "RsaPssRsaeSha384",
            "RsaPkcs1Sha384",
            "RsaPssRsaeSha512",
            "RsaPkcs1Sha512",
            "EcdsaSha1",
            "RsaPkcs1Sha1",
        ),
    ),
    "certificate_compression": ("CertificateCompression", ("Zlib", "Brotli", "Zstd")),
}


TLS_ENUM_LISTS["key_shares"] = TLS_ENUM_LISTS["groups"]


TLS_ENUM_LISTS["delegated_credential_schemes"] = TLS_ENUM_LISTS["signature_schemes"]


TLS_DELEGATED_SCHEMES = (
    "EcdsaSecp256r1Sha256",
    "EcdsaSecp384r1Sha384",
    "EcdsaSecp521r1Sha512",
    "EcdsaSha1",
)


TLS_EXTENSIONS = (
    "ServerName",
    "ExtendedMasterSecret",
    "RenegotiationInfo",
    "SupportedGroups",
    "EcPointFormats",
    "SessionTicket",
    "RecordSizeLimit",
    "Alpn",
    "StatusRequest",
    "SignedCertificateTimestamp",
    "KeyShare",
    "EarlyData",
    "SupportedVersions",
    "SignatureAlgorithms",
    "DelegatedCredential",
    "PskKeyExchangeModes",
    "CertificateCompression",
    "TrustAnchors",
    "ApplicationSettings",
    "ApplicationSettingsLegacy",
    "EncryptedClientHello",
    "QuicTransportParameters",
)


TLS_AEADS = ("Aes128Gcm", "Aes256Gcm", "ChaCha20Poly1305")


TLS_BOOLEAN_FIELDS = (
    "session_ticket_extension_when_resuming",
    "tcp_early_data",
    "tls12_extensions_in_tls13_client_hello",
    "grease",
    "grease_signature_algorithms",
    "request_ocsp_staple",
    "request_signed_certificate_timestamps",
    "aes_hardware",
    "close_notify",
)


def validate_tls_trust_anchors(value):
    if value is None:
        return
    keys(value, ("kind", "orders"), "TLS trust anchors")
    kind = choice(
        value["kind"],
        ("Fixed", "PerClient", "PerConnection"),
        "TLS trust anchor policy",
    )
    orders = value["orders"]
    bounded_list(orders, 1, 1 if kind == "Fixed" else 64, "TLS trust anchor candidates")
    expected = None
    for order in orders:
        bounded_list(order, 0, 4096, "TLS trust anchor IDs")
        for identifier in order:
            validate_bytes(identifier, 1, 255, "TLS trust anchor ID")
        if sum(1 + len(identifier) for identifier in order) > 65_533:
            raise DeclarationError("TLS trust anchor encoded list exceeds 65533 bytes")
        multiset = sorted(tuple(identifier) for identifier in order)
        if expected is not None and multiset != expected:
            raise DeclarationError(
                "TLS trust anchor candidates must preserve the same ID multiset"
            )
        expected = multiset


def validate_tls_ech(value):
    keys(value, ("kind", "settings"), "TLS ECH")
    kind = choice(
        value["kind"], ("Disabled", "Grease", "HttpsRecords"), "TLS ECH policy"
    )
    settings = value["settings"]
    if kind == "Disabled":
        if settings is not None:
            raise DeclarationError("Disabled ECH has no GREASE settings")
        return
    keys(settings, ("payload_length", "aeads"), "TLS ECH GREASE settings")
    payload = settings["payload_length"]
    keys(payload, ("kind", "value"), "TLS ECH GREASE payload")
    policy = choice(
        payload["kind"],
        ("BackendDefault", "Exact", "FromClientHello"),
        "TLS ECH payload policy",
    )
    if policy == "BackendDefault":
        if payload["value"] is not None:
            raise DeclarationError("BackendDefault ECH payload has no value")
    else:
        minimum, maximum = (1, 65_493) if policy == "Exact" else (0, 255)
        bounded_integer(payload["value"], minimum, maximum, "TLS ECH payload")
    aeads = settings["aeads"]
    bounded_list(aeads, 0, len(TLS_AEADS), "TLS ECH AEADs")
    for aead in aeads:
        choice(aead, TLS_AEADS, "TLS ECH AEAD")
    if len(set(aeads)) != len(aeads):
        raise DeclarationError("duplicate TLS ECH AEAD")


def validate_tls_values(values):
    versions = values["versions"]
    keys(versions, ("min", "max"), "TLS versions")
    for endpoint in versions.values():
        choice(endpoint, TLS_VERSIONS, "TLS version")
    if TLS_VERSIONS.index(versions["min"]) > TLS_VERSIONS.index(versions["max"]):
        raise DeclarationError("TLS version range is reversed")
    tls13 = versions["max"] == "Tls13"
    for field, (_, variants) in TLS_ENUM_LISTS.items():
        items = values[field]
        bounded_list(
            items,
            1 if field in ("cipher_suites", "groups", "signature_schemes") else 0,
            64,
            field,
        )
        for item in items:
            choice(item, variants, field)
    for scheme in values["delegated_credential_schemes"]:
        choice(scheme, TLS_DELEGATED_SCHEMES, "TLS delegated credential scheme")
    compression = values["certificate_compression"]
    if len(set(compression)) != len(compression):
        raise DeclarationError("duplicate TLS certificate compression algorithm")
    for field in TLS_BOOLEAN_FIELDS:
        boolean(values[field], field)
    tickets = values["session_tickets"]
    keys(tickets, ("enabled", "tcp_per_origin"), "TLS session tickets")
    boolean(tickets["enabled"], "TLS session tickets enabled")
    if tickets["enabled"]:
        bounded_integer(tickets["tcp_per_origin"], 1, 10, "TLS ticket limit")
    elif tickets["tcp_per_origin"] is not None:
        raise DeclarationError("disabled TLS tickets have no limit")
    choice(
        values["session_ticket_order"],
        ("NewestFirst", "OldestConnectionFirst", "OldestFirst"),
        "TLS ticket order",
    )
    if values["tcp_early_data"] and not tickets["enabled"]:
        raise DeclarationError("TCP early data requires TLS session tickets")
    if values["record_size_limit"] is not None:
        bounded_integer(
            values["record_size_limit"], 64, 16_385, "TLS record size limit"
        )
    validate_tls_trust_anchors(values["requested_trust_anchor_ids"])
    validate_tls_ech(values["ech"])
    if not tls13:
        if (
            values["tcp_early_data"]
            or values["key_shares"]
            or values["ech"]["kind"] != "Disabled"
            or values["requested_trust_anchor_ids"] is not None
            or values["certificate_compression"]
            or values["delegated_credential_schemes"]
            or values["alps"] is not None
        ):
            raise DeclarationError("TLS 1.3-only settings require TLS 1.3")
    elif not values["key_shares"] or any(
        group not in values["groups"] for group in values["key_shares"]
    ):
        raise DeclarationError(
            "TLS 1.3 requires key shares present in supported groups"
        )
    protocols = values["alpn_protocols"]
    bounded_list(protocols, 1, 256, "TLS ALPN protocols")
    for protocol in protocols:
        validate_bytes(protocol, 1, 255, "TLS ALPN protocol")
    if sum(1 + len(protocol) for protocol in protocols) > 65_535:
        raise DeclarationError("TLS ALPN encoded list exceeds 65535 bytes")
    alps = values["alps"]
    if alps is not None:
        keys(alps, ("protocol", "settings", "use_new_codepoint"), "TLS ALPS")
        validate_bytes(alps["protocol"], 1, 255, "TLS ALPS protocol")
        validate_bytes(alps["settings"], 0, 65_535, "TLS ALPS settings")
        boolean(alps["use_new_codepoint"], "TLS ALPS codepoint")
        if alps["protocol"] not in protocols:
            raise DeclarationError("TLS ALPS protocol is absent from ALPN")
    extension = values["extension_order"]
    keys(extension, ("kind", "extensions"), "TLS extension order")
    kind = choice(
        extension["kind"],
        ("BackendDefault", "Permuted", "Fixed", "PermutedWithTail"),
        "TLS extension policy",
    )
    extensions = extension["extensions"]
    bounded_list(
        extensions,
        1 if kind in ("Fixed", "PermutedWithTail") else 0,
        64,
        "TLS extension list",
    )
    for name in extensions:
        choice(name, TLS_EXTENSIONS, "TLS extension")
    if len(set(extensions)) != len(extensions):
        raise DeclarationError("duplicate TLS extension")
    if kind in ("BackendDefault", "Permuted") and extensions:
        raise DeclarationError("TLS extension policy has no fixed list")


def rust_trust_order(order):
    return (
        "crate::TrustAnchorOrder::from_recipe(vec!["
        + ", ".join(rust_bytes(identifier) for identifier in order)
        + "])"
    )


def rust_tls_ech(value):
    if value["kind"] == "Disabled":
        return "crate::EchSettings::Disabled"
    settings = value["settings"]
    payload = settings["payload_length"]
    length = f"crate::EchGreasePayloadLength::{payload['kind']}"
    if payload["kind"] == "Exact":
        length += f"({payload['value']})"
    elif payload["kind"] == "FromClientHello":
        length += f" {{ maximum_name_length: {payload['value']} }}"
    aeads = (
        "vec!["
        + ", ".join(f"crate::EchGreaseAead::{name}" for name in settings["aeads"])
        + "]"
    )
    grease = f"crate::EchGreaseSettings {{ payload_length: {length}, aeads: {aeads} }}"
    return f"crate::EchSettings::{value['kind']}({grease})"


def rust_tls_value(field, value):
    if field in TLS_ENUM_LISTS:
        enum = TLS_ENUM_LISTS[field][0]
        return "vec![" + ", ".join(f"crate::{enum}::{item}" for item in value) + "]"
    if field in TLS_BOOLEAN_FIELDS:
        return str(value).lower()
    if field == "versions":
        return f"crate::TlsVersionRange {{ min: crate::TlsVersion::{value['min']}, max: crate::TlsVersion::{value['max']} }}"
    if field == "alpn_protocols":
        return "vec![" + ", ".join(rust_bytes(protocol) for protocol in value) + "]"
    if field == "alps":
        return rust_option(
            value,
            lambda alps: (
                "crate::AlpsSettings { "
                + f"protocol: {rust_bytes(alps['protocol'])}, settings: {rust_bytes(alps['settings'])}, use_new_codepoint: {str(alps['use_new_codepoint']).lower()} "
                + "}"
            ),
        )
    if field == "session_tickets":
        if not value["enabled"]:
            return "crate::SessionTickets::disabled()"
        if value["tcp_per_origin"] == 2:
            return "crate::tls::TWO_SESSION_TICKETS"
        if value["tcp_per_origin"] == 10:
            return "crate::tls::TEN_SESSION_TICKETS"
        return f"crate::SessionTickets {{ tcp_per_origin: std::num::NonZeroU8::new({value['tcp_per_origin']}) }}"
    if field == "session_ticket_order":
        return f"crate::SessionTicketOrder::{value}"
    if field == "record_size_limit":
        return rust_option(value, str)
    if field == "requested_trust_anchor_ids":
        if value is None:
            return "None"
        orders = value["orders"]
        if value["kind"] == "Fixed":
            inner = rust_trust_order(orders[0])
        else:
            inner = (
                "crate::TrustAnchorOrders::from_recipe(vec!["
                + ", ".join(rust_trust_order(order) for order in orders)
                + "])"
            )
        return f"Some(crate::TrustAnchorIds::{value['kind']}({inner}))"
    if field == "extension_order":
        expression = f"crate::ClientHelloExtensionOrder::{value['kind']}"
        if value["kind"] in ("Fixed", "PermutedWithTail"):
            expression += (
                "(vec!["
                + ", ".join(
                    f"crate::ClientHelloExtension::{name}"
                    for name in value["extensions"]
                )
                + "])"
            )
        return expression
    return rust_tls_ech(value)


TLS_TRUST_CANDIDATE_VALIDATOR = """#[allow(dead_code, reason = "Rust 1.88 does not count anonymous const assertions as uses")]
const fn _valid_recipe_trust_candidates<const N: usize>(orders: &[&[&[u8]]], expected: &[(&[u8], usize); N]) -> bool {
    const fn compare_ids(left: &[u8], right: &[u8]) -> i8 {
        let mut index = 0;
        while index < left.len() && index < right.len() {
            if left[index] < right[index] { return -1; }
            if left[index] > right[index] { return 1; }
            index += 1;
        }
        if left.len() < right.len() { return -1; }
        if left.len() > right.len() { return 1; }
        0
    }
    if orders.is_empty() { return false; }
    let mut total = 0usize;
    let mut encoded = 0usize;
    let mut index = 0;
    while index < N {
        let (id, count) = expected[index];
        if id.is_empty() || id.len() > 255 || count == 0 { return false; }
        if index > 0 && compare_ids(expected[index - 1].0, id) >= 0 { return false; }
        let Some(next_total) = total.checked_add(count) else { return false; };
        total = next_total;
        let Some(bytes) = (id.len() + 1).checked_mul(count) else { return false; };
        let Some(next_encoded) = encoded.checked_add(bytes) else { return false; };
        encoded = next_encoded;
        index += 1;
    }
    if encoded > 65533 { return false; }
    let mut candidate = 0;
    while candidate < orders.len() {
        let order = orders[candidate];
        if order.len() != total { return false; }
        let mut counts = [0usize; N];
        let mut position = 0;
        while position < order.len() {
            let id = order[position];
            let mut low = 0;
            let mut high = N;
            let mut found = false;
            while low < high {
                let middle = low + (high - low) / 2;
                let comparison = compare_ids(id, expected[middle].0);
                if comparison < 0 { high = middle; }
                else if comparison > 0 { low = middle + 1; }
                else {
                    counts[middle] += 1;
                    found = true;
                    break;
                }
            }
            if !found { return false; }
            position += 1;
        }
        index = 0;
        while index < N {
            if counts[index] != expected[index].1 { return false; }
            index += 1;
        }
        candidate += 1;
    }
    true
}

#[cfg(test)]
#[rustfmt::skip]
#[test]
fn _trust_candidate_assertion_preserves_multisets_and_duplicate_slots() {
    let expected: &[(&[u8], usize); 2] = &[(&[1], 2), (&[2], 1)];
    assert!(_valid_recipe_trust_candidates(&[&[], &[]], &[]));
    assert!(_valid_recipe_trust_candidates(&[&[&[1], &[2], &[1]], &[&[2], &[1], &[1]], &[&[1], &[2], &[1]]], expected));
    assert!(_valid_recipe_trust_candidates(&[&[&[1, 0], &[1]]], &[(&[1], 1), (&[1, 0], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[], expected));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1], &[2], &[2]]], expected));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1], &[1]]], expected));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1], &[2], &[3]]], expected));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1, 2]]], &[(&[1, 3], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1]]], &[(&[1, 0], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1], &[2]]], &[(&[2], 1), (&[1], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1], &[1]]], &[(&[1], 1), (&[1], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[]], &[(&[1], 0)]));
    assert!(!_valid_recipe_trust_candidates(&[&[&[]]], &[(&[], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[]], &[(&[1; 256], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[]], &[(&[1; 255], 256)]));
    assert!(!_valid_recipe_trust_candidates(&[&[]], &[(&[1], usize::MAX)]));
}

#[cfg(test)]
#[rustfmt::skip]
#[test]
fn _trust_candidate_assertion_accepts_declared_count_ceilings() {
    let ids = (0..4096_u16).map(u16::to_be_bytes).collect::<Vec<_>>();
    let reference: [(&[u8], usize); 4096] = std::array::from_fn(|index| (ids[index].as_slice(), 1));
    let reversed = ids.iter().rev().map(|id| id.as_slice()).collect::<Vec<_>>();
    assert!(_valid_recipe_trust_candidates(&[reversed.as_slice(); 64], &reference));
}
"""
