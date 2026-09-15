use super::{
    ALPN_EXTENSION, ClientHelloDecodeError, ClientHelloSummary, EC_POINT_FORMATS_EXTENSION,
    KEY_SHARE_EXTENSION, SERVER_NAME_EXTENSION, SIGNATURE_ALGORITHMS_EXTENSION,
    SUPPORTED_GROUPS_EXTENSION, SUPPORTED_VERSIONS_EXTENSION, is_grease,
};

fn extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
    let length = u16::try_from(data.len()).unwrap_or_else(|_| panic!("test extension too long"));
    let mut encoded = extension_type.to_be_bytes().to_vec();
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(data);
    encoded
}

fn body(cipher_suites: &[u8], extensions: Option<&[u8]>) -> Vec<u8> {
    let cipher_length =
        u16::try_from(cipher_suites.len()).unwrap_or_else(|_| panic!("test vector too long"));
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x42; 32]);
    body.extend_from_slice(&[2, 0xaa, 0xbb]);
    body.extend_from_slice(&cipher_length.to_be_bytes());
    body.extend_from_slice(cipher_suites);
    body.extend_from_slice(&[1, 0]);
    if let Some(extensions) = extensions {
        let length =
            u16::try_from(extensions.len()).unwrap_or_else(|_| panic!("test vector too long"));
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(extensions);
    }
    body
}

fn handshake(body: &[u8]) -> Vec<u8> {
    let length = body.len();
    assert!(length <= 0x00ff_ffff);
    let mut message = vec![
        1,
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
    ];
    message.extend_from_slice(body);
    message
}

fn decode_body(body: &[u8]) -> Result<ClientHelloSummary, ClientHelloDecodeError> {
    ClientHelloSummary::decode(&handshake(body))
}

#[test]
fn decodes_ordered_fingerprint_fields() -> Result<(), ClientHelloDecodeError> {
    let mut extensions = extension(0x3a3a, &[1, 2, 3]);
    extensions.extend_from_slice(&extension(
        SERVER_NAME_EXTENSION,
        b"\x00\x16\x00\x00\x13server.phantom.test",
    ));
    extensions.extend_from_slice(&extension(
        SUPPORTED_GROUPS_EXTENSION,
        &[0, 4, 0, 29, 0x2a, 0x2a],
    ));
    extensions.extend_from_slice(&extension(EC_POINT_FORMATS_EXTENSION, &[3, 0, 2, 1]));
    extensions.extend_from_slice(&extension(
        SIGNATURE_ALGORITHMS_EXTENSION,
        &[0, 4, 0x08, 0x04, 0x04, 0x03],
    ));
    extensions.extend_from_slice(&extension(ALPN_EXTENSION, &[0, 5, 2, b'h', b'2', 1, 0xff]));
    extensions.extend_from_slice(&extension(
        SUPPORTED_VERSIONS_EXTENSION,
        &[4, 0x03, 0x04, 0x7a, 0x7a],
    ));
    extensions.extend_from_slice(&extension(
        KEY_SHARE_EXTENSION,
        &[0, 11, 0, 29, 0, 2, 1, 2, 0x4a, 0x4a, 0, 1, 3],
    ));

    let summary = decode_body(&body(
        &[0x13, 0x02, 0x0a, 0x0a, 0x13, 0x01],
        Some(&extensions),
    ))?;

    assert_eq!(summary.legacy_version(), 0x0303);
    assert_eq!(summary.cipher_suites(), &[0x1302, 0x0a0a, 0x1301]);
    assert_eq!(
        summary.extension_types(),
        &[0x3a3a, 0, 10, 11, 13, 16, 43, 51]
    );
    assert_eq!(
        summary.server_name(),
        Some(b"server.phantom.test".as_slice())
    );
    assert_eq!(summary.supported_groups(), &[29, 0x2a2a]);
    assert_eq!(summary.ec_point_formats(), &[0, 2, 1]);
    assert_eq!(summary.signature_algorithms(), &[0x0804, 0x0403]);
    assert_eq!(summary.alpn_protocols(), &[b"h2".to_vec(), vec![0xff]]);
    assert_eq!(summary.supported_versions(), &[0x0304, 0x7a7a]);
    assert_eq!(summary.key_share_groups(), &[29, 0x4a4a]);
    Ok(())
}

#[test]
fn identifies_only_grease_values() {
    for value in [0x0a0a, 0x1a1a, 0xaaaa, 0xfafa] {
        assert!(is_grease(value));
    }
    for value in [0x0a1a, 0x1a2a, 0x0a0b, 0x1301] {
        assert!(!is_grease(value));
    }
}

#[test]
fn accepts_absent_optional_extensions() -> Result<(), ClientHelloDecodeError> {
    let summary = decode_body(&body(&[0x13, 0x01], None))?;

    assert!(summary.extension_types().is_empty());
    assert_eq!(summary.server_name(), None);
    assert!(summary.supported_groups().is_empty());
    assert!(summary.ec_point_formats().is_empty());
    assert!(summary.signature_algorithms().is_empty());
    assert!(summary.alpn_protocols().is_empty());
    assert!(summary.supported_versions().is_empty());
    assert!(summary.key_share_groups().is_empty());
    Ok(())
}

#[test]
fn rejects_truncation_at_major_vectors() {
    let valid = body(&[0x13, 0x01], Some(&[]));
    for length in [0, 1, 2, 33, 34, 35, 37, 38, 39, valid.len() - 1] {
        assert!(matches!(
            decode_body(&valid[..length]),
            Err(ClientHelloDecodeError::Truncated { .. })
        ));
    }
}

#[test]
fn rejects_odd_u16_vector_lengths() {
    assert!(matches!(
        decode_body(&body(&[0x13, 0x01, 0xff], None)),
        Err(ClientHelloDecodeError::InvalidVectorLength {
            field: "cipher suites",
            ..
        })
    ));

    for (extension_type, data, field) in [
        (
            SUPPORTED_GROUPS_EXTENSION,
            vec![0, 3, 0, 29, 0],
            "supported groups",
        ),
        (
            SIGNATURE_ALGORITHMS_EXTENSION,
            vec![0, 3, 8, 4, 0],
            "signature algorithms",
        ),
        (
            SUPPORTED_VERSIONS_EXTENSION,
            vec![3, 3, 4, 0],
            "supported versions",
        ),
    ] {
        let extensions = extension(extension_type, &data);
        assert!(matches!(
            decode_body(&body(&[0x13, 0x01], Some(&extensions))),
            Err(ClientHelloDecodeError::InvalidVectorLength { field: found, .. })
                if found == field
        ));
    }
}

#[test]
fn rejects_malformed_nested_lengths() {
    for (extension_type, data) in [
        (SERVER_NAME_EXTENSION, vec![0, 4, 0, 0, 2, b'a']),
        (SUPPORTED_GROUPS_EXTENSION, vec![0, 4, 0, 29]),
        (EC_POINT_FORMATS_EXTENSION, vec![2, 0]),
        (SIGNATURE_ALGORITHMS_EXTENSION, vec![0, 4, 8, 4]),
        (ALPN_EXTENSION, vec![0, 3, 2, b'h']),
        (SUPPORTED_VERSIONS_EXTENSION, vec![4, 3, 4]),
        (KEY_SHARE_EXTENSION, vec![0, 6, 0, 29, 0, 4, 1]),
    ] {
        let extensions = extension(extension_type, &data);
        assert!(matches!(
            decode_body(&body(&[0x13, 0x01], Some(&extensions))),
            Err(ClientHelloDecodeError::Truncated { .. })
        ));
    }
}

#[test]
fn accepts_empty_key_share_list() -> Result<(), ClientHelloDecodeError> {
    let extensions = extension(KEY_SHARE_EXTENSION, &[0, 0]);

    let summary = decode_body(&body(&[0x13, 0x01], Some(&extensions)))?;

    assert!(summary.key_share_groups().is_empty());
    Ok(())
}

#[test]
fn rejects_empty_ec_point_formats() {
    let extensions = extension(EC_POINT_FORMATS_EXTENSION, &[0]);

    assert!(matches!(
        decode_body(&body(&[0x13, 0x01], Some(&extensions))),
        Err(ClientHelloDecodeError::LengthOutOfRange {
            field: "EC point formats",
            length: 0,
            ..
        })
    ));
}

#[test]
fn rejects_empty_key_exchange() {
    let extensions = extension(KEY_SHARE_EXTENSION, &[0, 4, 0, 29, 0, 0]);

    assert!(matches!(
        decode_body(&body(&[0x13, 0x01], Some(&extensions))),
        Err(ClientHelloDecodeError::LengthOutOfRange {
            field: "key exchange",
            length: 0,
            ..
        })
    ));
}

#[test]
fn rejects_empty_server_name_list_and_value() {
    for (data, expected) in [
        (
            vec![0, 0],
            ClientHelloDecodeError::LengthOutOfRange {
                field: "server name list",
                length: 0,
                minimum: 1,
                maximum: u16::MAX as usize,
            },
        ),
        (
            vec![0, 3, 0, 0, 0],
            ClientHelloDecodeError::EmptyServerName { name_type: 0 },
        ),
    ] {
        let extensions = extension(SERVER_NAME_EXTENSION, &data);
        assert_eq!(
            decode_body(&body(&[0x13, 0x01], Some(&extensions))),
            Err(expected)
        );
    }
}

#[test]
fn rejects_duplicate_server_name_types() {
    let extensions = extension(SERVER_NAME_EXTENSION, &[0, 8, 0, 0, 1, b'a', 0, 0, 1, b'b']);

    assert_eq!(
        decode_body(&body(&[0x13, 0x01], Some(&extensions))),
        Err(ClientHelloDecodeError::DuplicateServerNameType { name_type: 0 })
    );
}

#[test]
fn rejects_duplicate_extensions() {
    for (extension_type, data) in [
        (SERVER_NAME_EXTENSION, vec![0, 4, 0, 0, 1, b'a']),
        (SUPPORTED_GROUPS_EXTENSION, vec![0, 2, 0, 29]),
        (EC_POINT_FORMATS_EXTENSION, vec![1, 0]),
        (SIGNATURE_ALGORITHMS_EXTENSION, vec![0, 2, 8, 4]),
        (ALPN_EXTENSION, vec![0, 3, 2, b'h', b'2']),
        (SUPPORTED_VERSIONS_EXTENSION, vec![2, 3, 4]),
        (KEY_SHARE_EXTENSION, vec![0, 5, 0, 29, 0, 1, 1]),
        (0xfe0d, vec![0]),
        (0xbeef, vec![1]),
    ] {
        let mut extensions = extension(extension_type, &data);
        extensions.extend_from_slice(&extension(extension_type, &data));
        assert_eq!(
            decode_body(&body(&[0x13, 0x01], Some(&extensions))),
            Err(ClientHelloDecodeError::DuplicateExtension { extension_type })
        );
    }
}

#[test]
fn rejects_bytes_after_declared_extension_block() {
    let mut malformed = body(&[0x13, 0x01], Some(&[]));
    malformed.extend_from_slice(&[0xaa, 0xbb]);

    assert_eq!(
        decode_body(&malformed),
        Err(ClientHelloDecodeError::TrailingClientHelloBytes { count: 2 })
    );
}

#[test]
fn rejects_bytes_after_declared_handshake_body() {
    let body = body(&[0x13, 0x01], None);
    let mut message = handshake(&body);
    message.push(0xaa);

    assert_eq!(
        ClientHelloSummary::decode(&message),
        Err(ClientHelloDecodeError::TrailingHandshakeBytes { count: 1 })
    );
}

#[test]
fn rejects_trailing_bytes_inside_decoded_extensions() {
    let cases = [
        (SERVER_NAME_EXTENSION, vec![0, 4, 0, 0, 1, b'a', 0]),
        (SUPPORTED_GROUPS_EXTENSION, vec![0, 2, 0, 29, 0]),
        (EC_POINT_FORMATS_EXTENSION, vec![1, 0, 0]),
        (SIGNATURE_ALGORITHMS_EXTENSION, vec![0, 2, 8, 4, 0]),
        (ALPN_EXTENSION, vec![0, 3, 2, b'h', b'2', 0]),
        (SUPPORTED_VERSIONS_EXTENSION, vec![2, 3, 4, 0]),
        (KEY_SHARE_EXTENSION, vec![0, 5, 0, 29, 0, 1, 1, 0]),
    ];

    for (extension_type, data) in cases {
        let extensions = extension(extension_type, &data);
        assert!(matches!(
            decode_body(&body(&[0x13, 0x01], Some(&extensions))),
            Err(ClientHelloDecodeError::TrailingExtensionBytes {
                extension_type: found,
                count: 1,
            }) if found == extension_type
        ));
    }
}

#[test]
fn rejects_duplicate_unknown_extensions() {
    let mut extensions = extension(0xbeef, &[1]);
    extensions.extend_from_slice(&extension(0xbeef, &[2]));

    assert_eq!(
        decode_body(&body(&[0x13, 0x01], Some(&extensions))),
        Err(ClientHelloDecodeError::DuplicateExtension {
            extension_type: 0xbeef,
        })
    );
}
