//! Checked macOS intake for the paired system resolver owner.
//!
//! The paired owner must combine DNS, hosts-file and hostname invalidation
//! before caching combined results. DNS notifications alone do not provide it.

use crate::macos_dns_ffi::configuration::{
    ConfigurationError as NativeConfigurationError, read_macos_settings,
};
pub(super) use crate::macos_dns_ffi::{
    configuration::{
        MacDnsConfiguration as ConfigurationEligibility,
        SystemOnlyReason as ConfigurationIneligibility,
    },
    configuration_watch::{
        ConfigurationGeneration, ConfigurationObserver, ConfigurationWatch, WatchError,
    },
};
use std::{error::Error, fmt};

/// Retains the original bounded native errors without configuration values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConfigurationError {
    Watch(WatchError),
    Read(NativeConfigurationError),
    Changed,
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Watch(_) => f.write_str("macOS DNS watch failed during intake"),
            Self::Read(_) => f.write_str("macOS DNS settings read failed"),
            Self::Changed => f.write_str("macOS DNS configuration changed during intake"),
        }
    }
}

impl Error for ConfigurationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Watch(error) => Some(error),
            Self::Read(error) => Some(error),
            Self::Changed => None,
        }
    }
}

/// Samples only an already-started watch's expected generation. Start, check,
/// read and final shutdown belong to blocking work outside resolver/cache locks.
///
/// Missing native watch support remains an error from `ConfigurationWatch::start`.
/// A settings-level `SystemOnly` decision passes through before raw DNS work.
/// The caller must check again after preparing its resolver and fence publication
/// with the same observer generation. This is not an atomic OS snapshot.
pub(super) fn read_configuration(
    watch: &ConfigurationWatch,
    expected: &ConfigurationGeneration,
) -> Result<ConfigurationEligibility, ConfigurationError> {
    read_checked(|| watch.check(), expected, read_macos_settings)
}

fn read_checked<G: Eq>(
    check: impl Fn() -> Result<G, WatchError>,
    expected: &G,
    read: impl FnOnce() -> Result<ConfigurationEligibility, NativeConfigurationError>,
) -> Result<ConfigurationEligibility, ConfigurationError> {
    if check().map_err(ConfigurationError::Watch)? != *expected {
        return Err(ConfigurationError::Changed);
    }
    let settings = read().map_err(ConfigurationError::Read)?;
    if check().map_err(ConfigurationError::Watch)? != *expected {
        return Err(ConfigurationError::Changed);
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos_dns_ffi::{configuration::MacDnsSettings, configuration_watch::WatchCause};
    use std::{cell::Cell, net::SocketAddr, time::Duration};

    #[test]
    fn stable_intake_preserves_ordered_native_settings() -> Result<(), ConfigurationError> {
        let checks = Cell::new(0);
        let settings = read_checked(
            || {
                checks.set(checks.get() + 1);
                Ok(7)
            },
            &7,
            || {
                assert_eq!(checks.get(), 1);
                Ok(ConfigurationEligibility::BuiltIn(MacDnsSettings {
                    nameservers: vec![
                        SocketAddr::from(([127, 0, 0, 2], 5353)),
                        SocketAddr::from(([127, 0, 0, 1], 53)),
                    ],
                    search: vec!["first.test".into(), "second.test".into()],
                    ndots: 2,
                    attempts: 4,
                    retrans: Duration::from_secs(3),
                    rotate: true,
                }))
            },
        )?;
        assert_eq!(checks.get(), 2);
        let ConfigurationEligibility::BuiltIn(settings) = settings else {
            panic!("native settings became SystemOnly");
        };
        assert_eq!(
            settings.nameservers,
            [
                SocketAddr::from(([127, 0, 0, 2], 5353)),
                SocketAddr::from(([127, 0, 0, 1], 53)),
            ]
        );
        assert_eq!(settings.search, ["first.test", "second.test"]);
        assert_eq!(settings.ndots, 2);
        assert_eq!(settings.attempts, 4);
        assert_eq!(settings.retrans, Duration::from_secs(3));
        assert!(settings.rotate);
        Ok(())
    }

    #[test]
    fn system_only_reasons_pass_through_without_raw_resolver_construction()
    -> Result<(), ConfigurationError> {
        for reason in [
            ConfigurationIneligibility::WitnessUnavailable,
            ConfigurationIneligibility::Unsupported {
                resolver_options: true,
                multiple_resolvers: true,
            },
        ] {
            let settings = read_checked(
                || Ok(1),
                &1,
                || Ok(ConfigurationEligibility::SystemOnly(reason)),
            )?;
            assert!(
                matches!(settings, ConfigurationEligibility::SystemOnly(actual) if actual == reason)
            );
        }
        Ok(())
    }

    #[test]
    fn a_stale_generation_never_reads_native_settings() {
        let settings = read_checked(|| Ok(2), &1, || panic!("stale intake read settings"));
        assert!(matches!(settings, Err(ConfigurationError::Changed)));
    }

    #[test]
    fn a_change_during_read_cannot_publish_settings() {
        let generation = Cell::new(1);
        let settings = read_checked(
            || Ok(generation.get()),
            &1,
            || {
                generation.set(2);
                Ok(ConfigurationEligibility::SystemOnly(
                    ConfigurationIneligibility::WitnessUnavailable,
                ))
            },
        );
        assert!(matches!(settings, Err(ConfigurationError::Changed)));
    }

    #[test]
    fn original_watch_failures_before_and_after_read_are_preserved() {
        for cause in [
            WatchCause::WitnessUnavailable,
            WatchCause::Stopped,
            WatchCause::Native {
                operation: "notify_check",
                status: 3,
                code: 7,
            },
        ] {
            for after_read in [false, true] {
                let read_done = Cell::new(false);
                let error = WatchError {
                    cause,
                    cancellation: Some((4, 9)),
                };
                let settings = read_checked(
                    || {
                        if read_done.get() == after_read {
                            Err(error)
                        } else {
                            Ok(1)
                        }
                    },
                    &1,
                    || {
                        read_done.set(true);
                        Ok(ConfigurationEligibility::SystemOnly(
                            ConfigurationIneligibility::WitnessUnavailable,
                        ))
                    },
                );
                assert_eq!(read_done.get(), after_read);
                assert!(
                    matches!(settings, Err(ConfigurationError::Watch(actual)) if actual == error)
                );
            }
        }
    }

    #[test]
    fn a_native_read_failure_is_not_replaced_with_system_only() {
        let error = NativeConfigurationError::Native {
            status: 2,
            code: 13,
        };
        let checks = Cell::new(0);
        let settings = read_checked(
            || {
                checks.set(checks.get() + 1);
                Ok(1)
            },
            &1,
            || Err(error),
        );
        assert_eq!(checks.get(), 1);
        assert!(matches!(settings, Err(ConfigurationError::Read(actual)) if actual == error));
    }

    #[test]
    fn errors_preserve_typed_causes_without_settings_in_diagnostics() {
        let native = NativeConfigurationError::InvalidData("projection count");
        let error = ConfigurationError::Read(native);
        assert_eq!(
            error.source().and_then(|cause| cause.downcast_ref()),
            Some(&native)
        );
        let error = ConfigurationError::Changed;
        assert!(error.source().is_none());
        assert_eq!(
            error.to_string(),
            "macOS DNS configuration changed during intake"
        );
    }
}
