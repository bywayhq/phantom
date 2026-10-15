use std::error::Error;

use h3::client::{ApplicationSettingsError, SettingsError};

use super::TestResult;
use crate::http3::{Http3ErrorKind, validate_remembered_peer_settings};

#[test]
fn valid_remembered_settings_need_no_runtime() -> TestResult<()> {
    // QPACK table capacity 32, blocked streams 2, CONNECT and datagrams enabled.
    let settings = [4, 8, 1, 32, 7, 2, 8, 1, 0x33, 1];
    validate_remembered_peer_settings(&settings)?;
    Ok(())
}

#[test]
fn empty_settings_and_unknown_only_payloads_are_accepted() -> TestResult<()> {
    for payload in [&[][..], &[4, 0], &[0x21, 0], &[0x21, 0, 4, 0]] {
        validate_remembered_peer_settings(payload)?;
    }
    Ok(())
}

#[test]
fn truncated_frames_and_complete_truncated_settings_keep_the_parser_cause() -> TestResult<()> {
    for payload in [&[4][..], &[4, 2, 1], &[0x40], &[4, 0, 0x40]] {
        assert_invalid(payload, ApplicationSettingsError::Malformed)?;
    }
    assert_invalid(
        &[4, 1, 1],
        ApplicationSettingsError::Settings(SettingsError::Malformed),
    )?;
    Ok(())
}

#[test]
fn duplicate_known_unknown_and_multiple_settings_are_rejected() -> TestResult<()> {
    for identifier in [1, 0x21] {
        assert_invalid(
            &[4, 4, identifier, 0, identifier, 1],
            ApplicationSettingsError::Settings(SettingsError::Repeated(u64::from(identifier))),
        )?;
    }
    assert_invalid(&[4, 0, 4, 0], ApplicationSettingsError::MultipleSettings)?;
    Ok(())
}

#[test]
fn forbidden_identifiers_and_boolean_values_are_rejected() -> TestResult<()> {
    for identifier in [0, 2, 3, 4, 5] {
        assert_invalid(
            &[4, 2, identifier, 0],
            ApplicationSettingsError::Settings(SettingsError::InvalidSettingId(u64::from(
                identifier,
            ))),
        )?;
    }
    for identifier in [8, 0x33] {
        assert_invalid(
            &[4, 2, identifier, 2],
            ApplicationSettingsError::Settings(SettingsError::InvalidSettingValue(
                u64::from(identifier),
                2,
            )),
        )?;
    }
    Ok(())
}

#[test]
fn forbidden_application_frames_are_rejected() -> TestResult<()> {
    for payload in [&[0, 0][..], &[1, 0], &[2, 0], &[7, 1, 0], &[0x40, 0x4d, 0]] {
        assert_invalid(payload, ApplicationSettingsError::ForbiddenFrame)?;
    }
    Ok(())
}

#[test]
fn declared_oversize_is_rejected_without_imposing_a_retention_size_limit() -> TestResult<()> {
    // A complete maximum-width frame length cannot fit the supplied payload.
    assert_invalid(
        &[4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ApplicationSettingsError::Malformed,
    )?;

    // Unknown frames are skipped even above ApplicationState's retention bound.
    let mut unknown = vec![0x21, 0x44, 0x01];
    unknown.resize(1028, 0);
    validate_remembered_peer_settings(&unknown)?;
    Ok(())
}

fn assert_invalid(payload: &[u8], expected: ApplicationSettingsError) -> TestResult<()> {
    let error = validate_remembered_peer_settings(payload)
        .err()
        .ok_or("invalid remembered settings were accepted")?;
    assert_eq!(error.kind(), Http3ErrorKind::Protocol);
    assert_eq!(error.unprocessed(), None);
    assert_eq!(error.to_string(), "remembered HTTP/3 SETTINGS are invalid");
    let cause = error
        .source()
        .and_then(|source| source.downcast_ref::<ApplicationSettingsError>())
        .ok_or("the original settings parser error was not retained")?;
    assert_eq!(*cause, expected);
    Ok(())
}
