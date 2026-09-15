use super::{Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings, InvalidHttp2Settings};

fn settings() -> Http2Settings {
    Http2Settings {
        initial_settings: vec![
            Http2Setting::HeaderTableSize(4_096),
            Http2Setting::InitialWindowSize(65_535),
        ],
        initial_connection_window_size: 65_535,
        pseudo_header_order: vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
            Http2PseudoHeader::Path,
        ],
        headers_priority: None,
    }
}

#[test]
fn accepts_owned_customizable_settings() -> Result<(), Box<dyn std::error::Error>> {
    let mut settings = settings();
    settings.initial_settings[0] = Http2Setting::HeaderTableSize(65_536);
    settings.headers_priority = Some(Http2Priority {
        dependency_stream_id: 0,
        weight: 256,
        exclusive: true,
    });

    settings.validate()?;
    Ok(())
}

#[test]
fn rejects_duplicate_initial_settings() {
    let mut settings = settings();
    settings
        .initial_settings
        .push(Http2Setting::HeaderTableSize(1));

    assert_field(settings.validate(), "initial_settings");
}

#[test]
fn requires_one_initial_stream_window() {
    let mut settings = settings();
    settings
        .initial_settings
        .retain(|setting| !matches!(setting, Http2Setting::InitialWindowSize(_)));

    assert_field(settings.validate(), "initial_settings");
}

#[test]
fn rejects_stream_window_overflow() {
    let mut stream = settings();
    stream.initial_settings[1] = Http2Setting::InitialWindowSize(1 << 31);
    assert_field(stream.validate(), "initial_settings.initial_window_size");
}

#[test]
fn validates_connection_window_range() -> Result<(), Box<dyn std::error::Error>> {
    let mut below_minimum = settings();
    below_minimum.initial_connection_window_size = 65_534;
    assert_field(below_minimum.validate(), "initial_connection_window_size");

    let mut minimum = settings();
    minimum.initial_connection_window_size = 65_535;
    minimum.validate()?;

    let mut maximum = settings();
    maximum.initial_connection_window_size = (1 << 31) - 1;
    maximum.validate()?;

    let mut above_maximum = settings();
    above_maximum.initial_connection_window_size = 1 << 31;
    assert_field(above_maximum.validate(), "initial_connection_window_size");

    Ok(())
}

#[test]
fn rejects_invalid_maximum_frame_sizes() {
    for size in [16_383, 16_777_216] {
        let mut settings = settings();
        settings
            .initial_settings
            .push(Http2Setting::MaxFrameSize(size));

        assert_field(settings.validate(), "initial_settings.max_frame_size");
    }
}

#[test]
fn requires_each_request_pseudo_header_once() {
    let mut missing = settings();
    missing.pseudo_header_order.pop();
    assert_field(missing.validate(), "pseudo_header_order");

    let mut duplicate = settings();
    duplicate.pseudo_header_order[3] = Http2PseudoHeader::Method;
    assert_field(duplicate.validate(), "pseudo_header_order");
}

#[test]
fn rejects_invalid_header_priority() {
    for (priority, field) in [
        (
            Http2Priority {
                dependency_stream_id: 1 << 31,
                weight: 16,
                exclusive: false,
            },
            "headers_priority.dependency_stream_id",
        ),
        (
            Http2Priority {
                dependency_stream_id: 0,
                weight: 0,
                exclusive: false,
            },
            "headers_priority.weight",
        ),
        (
            Http2Priority {
                dependency_stream_id: 0,
                weight: 257,
                exclusive: false,
            },
            "headers_priority.weight",
        ),
    ] {
        let mut settings = settings();
        settings.headers_priority = Some(priority);
        assert_field(settings.validate(), field);
    }
}

fn assert_field(result: Result<(), InvalidHttp2Settings>, expected_field: &'static str) {
    assert_eq!(
        result.as_ref().map_err(InvalidHttp2Settings::field),
        Err(expected_field)
    );
}
