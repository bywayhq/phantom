use std::{num::NonZeroU32, time::Duration};

use super::{
    MAX_TCP_FALLBACK_DELAY, MAX_TCP_KEEPALIVE_PROBES, MAX_TCP_KEEPALIVE_SECONDS,
    MAX_TCP_SHORT_LIVED_SECONDS, TcpAddressAdvance, TcpAddressRacing, TcpAddressSelection,
    TcpBackupConnection, TcpKeepalive, TcpKeepalivePolicy, TcpKeepaliveSchedule, TcpSettings,
};

fn with_keepalive(idle: Duration, interval: Option<Duration>) -> TcpSettings {
    TcpSettings {
        nodelay: true,
        keepalive: TcpKeepalivePolicy::Fixed(TcpKeepalive { idle, interval }),
        ..TcpSettings::default()
    }
}

fn with_selection(address_selection: TcpAddressSelection) -> TcpSettings {
    TcpSettings {
        nodelay: true,
        address_selection,
        ..TcpSettings::default()
    }
}

fn schedule() -> TcpKeepaliveSchedule {
    TcpKeepaliveSchedule {
        short_lived_idle: Duration::from_secs(10),
        long_lived_idle: Duration::from_secs(600),
        minimum_interval: Duration::from_secs(1),
        short_lived_time: Duration::from_secs(60),
        probe_count: 10,
    }
}

fn with_schedule(schedule: TcpKeepaliveSchedule) -> TcpSettings {
    TcpSettings {
        keepalive: TcpKeepalivePolicy::Schedule(schedule),
        ..TcpSettings::default()
    }
}

fn rejected_field(settings: TcpSettings) -> &'static str {
    match settings.validate() {
        Ok(()) => panic!("{settings:?} was accepted"),
        Err(error) => error.field(),
    }
}

#[test]
fn default_settings_ask_for_nothing_and_are_valid() {
    let settings = TcpSettings::default();

    assert!(!settings.nodelay);
    assert_eq!(settings.send_buffer_size, None);
    assert_eq!(settings.keepalive, TcpKeepalivePolicy::Unchanged);
    assert_eq!(
        settings.address_selection,
        TcpAddressSelection::Sequential(TcpAddressAdvance::AfterAnyFailure)
    );
    assert_eq!(settings.port_randomization, None);
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
        assert_eq!(rejected_field(with_keepalive(idle, None)), "keepalive.idle");
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

#[test]
fn a_firefox_style_schedule_is_valid() {
    assert_eq!(with_schedule(schedule()).validate(), Ok(()));
    let longest = TcpKeepaliveSchedule {
        short_lived_time: Duration::from_secs(MAX_TCP_SHORT_LIVED_SECONDS),
        ..schedule()
    };
    assert_eq!(with_schedule(longest).validate(), Ok(()));
}

#[test]
fn schedule_times_outside_bounds_are_rejected() {
    let cases = [
        (
            TcpKeepaliveSchedule {
                short_lived_idle: Duration::ZERO,
                ..schedule()
            },
            "keepalive.short_lived_idle",
        ),
        (
            TcpKeepaliveSchedule {
                long_lived_idle: Duration::from_millis(600_500),
                ..schedule()
            },
            "keepalive.long_lived_idle",
        ),
        (
            TcpKeepaliveSchedule {
                minimum_interval: Duration::from_secs(MAX_TCP_KEEPALIVE_SECONDS + 1),
                ..schedule()
            },
            "keepalive.minimum_interval",
        ),
        (
            TcpKeepaliveSchedule {
                short_lived_time: Duration::from_secs(MAX_TCP_SHORT_LIVED_SECONDS + 1),
                ..schedule()
            },
            "keepalive.short_lived_time",
        ),
        (
            TcpKeepaliveSchedule {
                short_lived_time: Duration::ZERO,
                ..schedule()
            },
            "keepalive.short_lived_time",
        ),
        (
            TcpKeepaliveSchedule {
                probe_count: 0,
                ..schedule()
            },
            "keepalive.probe_count",
        ),
        (
            TcpKeepaliveSchedule {
                probe_count: MAX_TCP_KEEPALIVE_PROBES + 1,
                ..schedule()
            },
            "keepalive.probe_count",
        ),
    ];
    for (schedule, field) in cases {
        assert_eq!(rejected_field(with_schedule(schedule)), field);
    }
}

#[test]
fn send_buffer_size_must_fit_the_socket_option() {
    let mut settings = TcpSettings {
        send_buffer_size: NonZeroU32::new(524_288),
        ..TcpSettings::default()
    };
    assert_eq!(settings.validate(), Ok(()));

    settings.send_buffer_size = NonZeroU32::new(u32::MAX);
    assert_eq!(rejected_field(settings), "send_buffer_size");
}

#[test]
fn delay_bounds_are_inclusive() {
    for delay in [Duration::from_millis(1), MAX_TCP_FALLBACK_DELAY] {
        let racing = TcpAddressSelection::Racing(TcpAddressRacing {
            fallback_delay: delay,
        });
        let backup = TcpAddressSelection::Backup(TcpBackupConnection { delay });
        assert_eq!(with_selection(racing).validate(), Ok(()));
        assert_eq!(with_selection(backup).validate(), Ok(()));
    }
}

#[test]
fn delays_outside_bounds_are_rejected() {
    for delay in [
        Duration::ZERO,
        MAX_TCP_FALLBACK_DELAY + Duration::from_nanos(1),
    ] {
        let racing = TcpAddressSelection::Racing(TcpAddressRacing {
            fallback_delay: delay,
        });
        let backup = TcpAddressSelection::Backup(TcpBackupConnection { delay });
        assert_eq!(
            rejected_field(with_selection(racing)),
            "address_selection.fallback_delay"
        );
        assert_eq!(
            rejected_field(with_selection(backup)),
            "address_selection.delay"
        );
    }
}
