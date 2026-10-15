use super::*;

const V1: u32 = 0x0000_0001;
const V2: u32 = 0x6b33_43cf;

fn version_information(chosen: u32) -> [u8; 6] {
    let mut parameter = [0x11, 4, 0, 0, 0, 0];
    parameter[2..].copy_from_slice(&chosen.to_be_bytes());
    parameter
}

#[test]
fn remembered_server_accepts_both_actual_versions_with_or_without_optional_information() {
    for version in [V1, V2] {
        assert_eq!(
            TransportParameters::validate_remembered_server(&[], version),
            Ok(())
        );
        let parameter = version_information(version);
        // A server may omit Available Versions entirely.
        assert_eq!(
            TransportParameters::validate_remembered_server(&parameter, version),
            Ok(())
        );
        let mut available = vec![0x11, 8];
        available.extend_from_slice(&version.to_be_bytes());
        available.extend_from_slice(&version.to_be_bytes());
        assert_eq!(
            TransportParameters::validate_remembered_server(&available, version),
            Ok(())
        );
    }
}

#[test]
fn remembered_server_rejects_deferred_version_errors_without_changing_normal_reading() {
    for (parameter, expected) in [
        (&[0x11, 3, 0, 0, 1][..], Error::Malformed),
        (&[0x11, 4, 0, 0, 0, 0][..], Error::IllegalValue),
        (&[0x11, 8, 0, 0, 0, 1, 0, 0, 0, 0][..], Error::IllegalValue),
    ] {
        let mut input = parameter;
        let ordinary = TransportParameters::read(Side::Client, &mut input)
            .unwrap_or_else(|error| panic!("normal reader unexpectedly failed: {error}"));
        assert_eq!(ordinary.version_information_error, Some(expected));
        for version in [V1, V2] {
            assert_eq!(
                TransportParameters::validate_remembered_server(parameter, version),
                Err(expected)
            );
        }
    }
}

#[test]
fn remembered_server_rejects_duplicate_version_information_even_when_both_values_match() {
    for version in [V1, V2] {
        let mut parameter = version_information(version).to_vec();
        parameter.extend_from_slice(&version_information(version));
        let ordinary = TransportParameters::read(Side::Client, &mut &parameter[..])
            .unwrap_or_else(|error| panic!("normal reader unexpectedly failed: {error}"));
        assert_eq!(
            ordinary.version_information.map(|info| info.chosen),
            Some(version)
        );
        assert_eq!(ordinary.version_information_error, Some(Error::Malformed));
        assert_eq!(
            TransportParameters::validate_remembered_server(&parameter, version),
            Err(Error::Malformed)
        );
    }
}

#[test]
fn remembered_server_checks_present_chosen_version_against_the_actual_ticket_version() {
    for (actual, chosen) in [(V1, V2), (V2, V1)] {
        let parameter = version_information(chosen);
        let ordinary = TransportParameters::read(Side::Client, &mut &parameter[..])
            .unwrap_or_else(|error| panic!("normal reader unexpectedly failed: {error}"));
        assert_eq!(ordinary.version_information_error, None);
        assert_eq!(
            ordinary.version_information.map(|info| info.chosen),
            Some(chosen)
        );
        assert_eq!(
            TransportParameters::validate_remembered_server(&parameter, actual),
            Err(Error::IllegalValue)
        );
    }
}

#[test]
fn remembered_server_rejects_unsupported_actual_versions_without_a_fallback() {
    for version in [0, 2, 0xff00_001d, 0x0a0a_0a0a, u32::MAX] {
        assert_eq!(
            TransportParameters::validate_remembered_server(&[], version),
            Err(Error::IllegalValue)
        );
        assert_eq!(
            TransportParameters::validate_remembered_server(&version_information(V1), version),
            Err(Error::IllegalValue)
        );
    }
}

#[test]
fn remembered_server_requires_complete_framing_and_keeps_well_formed_unknown_parameters() {
    for version in [V1, V2] {
        let parameter = version_information(version);
        for len in 1..parameter.len() {
            assert_eq!(
                TransportParameters::validate_remembered_server(&parameter[..len], version),
                Err(Error::Malformed)
            );
        }
        let mut trailing = parameter.to_vec();
        // An incomplete two-byte parameter identifier cannot be ignored.
        trailing.push(0x40);
        assert_eq!(
            TransportParameters::validate_remembered_server(&trailing, version),
            Err(Error::Malformed)
        );
        let mut unknown = parameter.to_vec();
        unknown.extend_from_slice(&[0x1b, 0]);
        assert_eq!(
            TransportParameters::validate_remembered_server(&unknown, version),
            Ok(())
        );
    }
}

#[test]
fn remembered_server_keeps_ordinary_duplicate_and_semantic_validation() {
    for version in [V1, V2] {
        // Two Initial Max Data parameters, both zero.
        let duplicate = [4, 1, 0, 4, 1, 0];
        assert_eq!(
            TransportParameters::validate_remembered_server(&duplicate, version),
            Err(Error::Malformed)
        );
        // ACK Delay Exponent exceeds the protocol maximum of 20.
        let illegal = [0x0a, 1, 21];
        assert_eq!(
            TransportParameters::validate_remembered_server(&illegal, version),
            Err(Error::IllegalValue)
        );
    }
}

#[test]
fn remembered_server_accepts_old_connection_ids_without_comparing_them_to_a_new_connection() {
    let remembered = TransportParameters {
        initial_src_cid: Some(ConnectionId::new(&[1, 2, 3])),
        original_dst_cid: Some(ConnectionId::new(&[4, 5, 6])),
        retry_src_cid: Some(ConnectionId::new(&[7, 8, 9])),
        ..TransportParameters::default()
    };
    let mut bytes = Vec::new();
    remembered.write(&mut bytes);
    for version in [V1, V2] {
        assert_eq!(
            TransportParameters::validate_remembered_server(&bytes, version),
            Ok(())
        );
    }
}
