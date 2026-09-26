//! Reads retained `scripts/capture/client_hints.py` navigation captures.

use std::collections::BTreeMap;

use crate::client_hints::{ClientHintDelivery, ClientHintSettings};

type CaptureResult<T> = Result<T, Box<dyn std::error::Error>>;

const FORMAT: &str = "phantom-client-hints-v2";

/// One `format=phantom-client-hints-v2` fixture.
pub(crate) struct NavigationCapture<'a> {
    fields: BTreeMap<&'a str, &'a str>,
}

impl<'a> NavigationCapture<'a> {
    pub(crate) fn parse(input: &'a str) -> CaptureResult<Self> {
        let mut fields = BTreeMap::new();
        for line in input.lines() {
            let (key, value) = line.split_once('=').ok_or("capture line is missing `=`")?;
            if fields.insert(key, value).is_some() {
                return Err(format!("capture repeats {key}").into());
            }
        }
        let capture = Self { fields };
        if capture.value("format")? != FORMAT {
            return Err("unexpected client-hint capture format".into());
        }
        Ok(capture)
    }

    pub(crate) fn value(&self, key: &str) -> CaptureResult<&'a str> {
        self.fields
            .get(key)
            .copied()
            .ok_or_else(|| format!("capture omitted {key}").into())
    }

    /// Returns `(delivery, name, value)` in second-navigation order.
    pub(crate) fn hints(&self) -> CaptureResult<Vec<(ClientHintDelivery, &'a str, &'a [u8])>> {
        let count: usize = self.value("hint_count")?.parse()?;
        (0..count)
            .map(|index| {
                let mut parts = self.value(&format!("hint_{index}"))?.splitn(3, '|');
                let delivery = match parts.next() {
                    Some("default") => ClientHintDelivery::Default,
                    Some("accept-ch") => ClientHintDelivery::AcceptCh,
                    _ => return Err("client-hint delivery is invalid".into()),
                };
                let name = parts.next().ok_or("client-hint name is missing")?;
                let value = parts.next().ok_or("client-hint value is missing")?;
                Ok((delivery, name, value.as_bytes()))
            })
            .collect()
    }

    /// Asserts that every run saw the derived default and requested sets.
    ///
    /// The capture tool refuses to write disagreeing runs; this re-derives
    /// the result from the per-run lines so the fixture cannot drift.
    pub(crate) fn assert_runs_agree(&self) -> CaptureResult<()> {
        let hints = self.hints()?;
        let defaults = hints
            .iter()
            .filter(|(delivery, _, _)| *delivery == ClientHintDelivery::Default)
            .map(|(_, name, value)| format!("{name}|{}", String::from_utf8_lossy(value)))
            .collect::<Vec<_>>();
        let all = hints
            .iter()
            .map(|(_, name, value)| format!("{name}|{}", String::from_utf8_lossy(value)))
            .collect::<Vec<_>>();
        let runs: usize = self.value("repeat_count")?.parse()?;
        if runs == 0 {
            return Err("capture has no runs".into());
        }
        for run in 0..runs {
            for (label, expected) in [("first", &defaults), ("second", &all)] {
                let key = format!("run_{run}_{label}_hint");
                let count: usize = self.value(&format!("{key}_count"))?.parse()?;
                let observed = (0..count)
                    .map(|index| self.value(&format!("{key}_{index}")))
                    .collect::<CaptureResult<Vec<_>>>()?;
                if observed != *expected {
                    return Err(format!("run {run} {label} navigation disagrees").into());
                }
            }
        }
        Ok(())
    }
}

/// Returns a profile's hints as `(delivery, name, value)` for comparison.
pub(crate) fn profile_hints(
    settings: &ClientHintSettings,
) -> Vec<(ClientHintDelivery, &str, &[u8])> {
    settings
        .hints()
        .iter()
        .map(|hint| (hint.delivery(), hint.name(), hint.value()))
        .collect()
}

/// Returns the `(name, value)` of each hint of `other` whose value differs
/// from the hint at the same position in `base`, after checking that both
/// carry the same names in the same order.
pub(crate) fn changed_hints(
    base: &ClientHintSettings,
    other: &ClientHintSettings,
) -> Vec<(String, String)> {
    let names = |settings: &ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| hint.name().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(names(base), names(other));
    base.hints()
        .iter()
        .zip(other.hints())
        .filter(|(base, other)| base.value() != other.value())
        .map(|(_, other)| {
            (
                other.name().to_owned(),
                String::from_utf8_lossy(other.value()).into_owned(),
            )
        })
        .collect()
}
