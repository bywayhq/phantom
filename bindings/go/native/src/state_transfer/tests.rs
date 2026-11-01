use super::*;

#[test]
fn timestamp_preserves_nanoseconds_before_epoch_and_after_unix_nano_range() -> Result<(), Failure> {
    for timestamp in [
        Timestamp {
            seconds: -1,
            nanoseconds: 345_678_900,
        },
        Timestamp {
            seconds: 253_402_300_798,
            nanoseconds: 123_456_700,
        },
    ] {
        assert_eq!(Timestamp::encode(timestamp.decode()?)?, timestamp);
    }
    assert!(
        Timestamp {
            seconds: 0,
            nanoseconds: 1_000_000_000
        }
        .decode()
        .is_err()
    );
    let sub_tick = Timestamp {
        seconds: 2_000_000_000,
        nanoseconds: 1,
    };
    #[cfg(windows)]
    assert!(sub_tick.decode().is_err());
    #[cfg(not(windows))]
    assert_eq!(Timestamp::encode(sub_tick.decode()?)?, sub_tick);
    Ok(())
}

#[test]
fn borrowed_rows_reject_alias_amplification_and_invalid_ranges() -> Result<(), Failure> {
    let row = Cookie {
        source_scheme: 2,
        value: Text {
            offset: 0,
            length: MAX_TEXT as u64,
        },
        ..Cookie::default()
    };
    let arena = vec![b'x'; MAX_TEXT];
    assert_eq!(
        cookies(&[row, row], &arena).err().map(|error| error.kind),
        Some("input_limit")
    );
    assert!(
        cookies(
            &[Cookie {
                name: Text {
                    offset: u64::MAX,
                    length: 1
                },
                source_scheme: 2,
                ..Cookie::default()
            }],
            &[]
        )
        .is_err()
    );
    assert!(
        cookies(
            &[Cookie {
                source_scheme: 2,
                flags: 32,
                ..Cookie::default()
            }],
            &[]
        )
        .is_err()
    );
    assert!(
        alternatives(
            &[Alternative {
                port: 65_536,
                ..Alternative::default()
            }],
            &[]
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn typed_cookie_import_retains_atomic_entry_failure_and_existing_state() -> Result<(), Failure> {
    let profile = crate::profile::named("chrome-154-windows", None)?;
    let client = Client::builder(profile)
        .cookies()
        .build()
        .map_err(Failure::from)?;
    client
        .cookie_jar()
        .ok_or_else(|| Failure::new("test_jar"))?
        .set_cookie("https://example.com/", "held=original; Secure; Path=/")
        .map_err(|_| Failure::new("test_cookie"))?;
    let snapshot = CookieSnapshot::new(vec![
        CookieSnapshotEntry::new(
            CookieSourceScheme::Https,
            "added",
            "first",
            "example.com",
            "/",
        ),
        CookieSnapshotEntry::new(
            CookieSourceScheme::Https,
            "bad",
            "second",
            "UPPER.invalid",
            "/",
        ),
    ]);
    let result = execute(&client, Input::ImportCookies(snapshot));
    assert_eq!(
        result.error.map(|error| error.kind),
        Some("cookie_snapshot_invalid_cookie")
    );
    assert_eq!(result.entry, Some(1));
    let held = client
        .export_cookies()
        .ok_or_else(|| Failure::new("test_jar"))?;
    assert_eq!(held.len(), 1);
    assert_eq!(held.entries()[0].name(), "held");
    Ok(())
}
