use phantom::{RequestTimeoutOverrides, RequestTimeouts, TimeoutOverride};
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum Timeout {
    Inherit {},
    Disabled {},
    Limit { nanoseconds: u64 },
}

impl Default for Timeout {
    fn default() -> Self {
        Self::Inherit {}
    }
}

impl Timeout {
    const fn into_override(self) -> TimeoutOverride {
        match self {
            Self::Inherit {} => TimeoutOverride::Inherit,
            Self::Disabled {} => TimeoutOverride::Disabled,
            Self::Limit { nanoseconds } => {
                TimeoutOverride::Limit(Duration::from_nanos(nanoseconds))
            }
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Timeouts {
    pool_admission: Timeout,
    connect: Timeout,
    response_head: Timeout,
    read_idle: Timeout,
    total: Timeout,
}

impl Timeouts {
    pub(super) const fn overrides(self) -> RequestTimeoutOverrides {
        RequestTimeoutOverrides::new()
            .pool_admission(self.pool_admission.into_override())
            .connect(self.connect.into_override())
            .response_head(self.response_head.into_override())
            .read_idle(self.read_idle.into_override())
            .total(self.total.into_override())
    }

    pub(super) const fn defaults(self) -> RequestTimeouts {
        self.overrides().resolve(RequestTimeouts::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_phase_distinguishes_inherit_disabled_and_zero() -> Result<(), serde_json::Error> {
        let defaults = RequestTimeouts::new()
            .pool_admission(Duration::from_secs(1))
            .connect(Duration::from_secs(2))
            .response_head(Duration::from_secs(3))
            .read_idle(Duration::from_secs(4))
            .total(Duration::from_secs(5));
        let inherited: Timeouts = serde_json::from_str("{}")?;
        assert_eq!(inherited.overrides().resolve(defaults), defaults);
        let inherited: Timeouts = serde_json::from_str(r#"{"total":{"mode":"inherit"}}"#)?;
        assert_eq!(inherited.overrides().resolve(defaults), defaults);
        for mode in ["disabled", "limit"] {
            let value = if mode == "limit" {
                serde_json::json!({"mode":mode,"nanoseconds":0})
            } else {
                serde_json::json!({"mode":mode})
            };
            let settings: Timeouts = serde_json::from_value(serde_json::json!({
                "pool_admission":value,"connect":value,"response_head":value,
                "read_idle":value,"total":value,
            }))?;
            let resolved = settings.overrides().resolve(defaults);
            let expected = (mode == "limit").then_some(Duration::ZERO);
            assert_eq!(resolved.pool_admission_duration(), expected);
            assert_eq!(resolved.connect_duration(), expected);
            assert_eq!(resolved.response_head_duration(), expected);
            assert_eq!(resolved.read_idle_duration(), expected);
            assert_eq!(resolved.total_duration(), expected);
        }
        let settings: Timeouts =
            serde_json::from_str(r#"{"connect":{"mode":"limit","nanoseconds":7}}"#)?;
        let defaults = settings.defaults();
        assert_eq!(defaults.connect_duration(), Some(Duration::from_nanos(7)));
        assert_eq!(defaults.total_duration(), None);
        Ok(())
    }

    #[test]
    fn malformed_modes_and_extra_duration_fields_fail() {
        for input in [
            r#"{"total":{"mode":"other"}}"#,
            r#"{"total":{"mode":"limit"}}"#,
            r#"{"total":{"mode":"limit","nanoseconds":-1}}"#,
            r#"{"total":{"mode":"disabled","nanoseconds":0}}"#,
            r#"{"total":{"mode":"inherit","nanoseconds":0}}"#,
            r#"{"total":{"mode":"disabled","unexpected":true}}"#,
            r#"{"total":{"mode":"inherit","unexpected":true}}"#,
            r#"{"total":{"mode":"limit","nanoseconds":0,"unexpected":true}}"#,
        ] {
            assert!(serde_json::from_str::<Timeouts>(input).is_err(), "{input}");
        }
    }
}
