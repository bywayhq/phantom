use std::time::Duration;

use super::{MAX_TCP_KEEPALIVE_SECONDS, TcpKeepalive, TcpSettings};

fn with_keepalive(idle: Duration, interval: Option<Duration>) -> TcpSettings {
    TcpSettings {
        nodelay: true,
        keepalive: Some(TcpKeepalive { idle, interval }),
    }
}

#[test]
fn settings_without_keepalive_are_valid() {
    let settings = TcpSettings {
        nodelay: false,
        keepalive: None,
    };

    assert_eq!(settings.validate(), Ok(()));
}

#[test]
fn keepalive_bounds_are_inclusive_whole_seconds() {
    let max = Duration::from_secs(MAX_TCP_KEEPALIVE_SECONDS);

    assert_eq!(
        with_keepalive(Duration::from_secs(1), Some(max)).validate(),
        Ok(())
    );
    assert_eq!(with_keepalive(max, None).validate(), Ok(()));
}

#[test]
fn keepalive_idle_outside_bounds_is_rejected() {
    for idle in [
        Duration::ZERO,
        Duration::from_millis(1_500),
        Duration::from_secs(MAX_TCP_KEEPALIVE_SECONDS + 1),
    ] {
        let error = match with_keepalive(idle, None).validate() {
            Ok(()) => panic!("{idle:?} was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.field(), "keepalive.idle");
    }
}

#[test]
fn keepalive_interval_outside_bounds_is_rejected() {
    let error = match with_keepalive(Duration::from_secs(45), Some(Duration::ZERO)).validate() {
        Ok(()) => panic!("a zero interval was accepted"),
        Err(error) => error,
    };

    assert_eq!(error.field(), "keepalive.interval");
    assert_eq!(
        error.to_string(),
        "invalid TCP keepalive.interval: keepalive times must be whole seconds in 1..=32767"
    );
}
