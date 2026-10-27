//! Explicit pool overrides owned before client construction.

use std::{num::NonZeroUsize, time::Duration};

use phantom::ClientBuilder;
use pyo3::{
    prelude::*,
    types::{PyFloat, PyInt},
};

use crate::error;

const COUNT_FIELDS: [&str; 11] = [
    "max_retained_http1_connections",
    "max_concurrent_http1_requests_per_origin",
    "max_pending_http1_requests_per_origin",
    "max_retained_http2_connections",
    "max_concurrent_http2_requests_per_origin",
    "max_pending_http2_requests_per_origin",
    "max_http2_connections_per_origin",
    "max_retained_http3_connections",
    "max_concurrent_http3_requests_per_origin",
    "max_pending_http3_requests_per_origin",
    "max_http3_connections_per_origin",
];

#[derive(Default)]
pub(super) struct Pool {
    counts: [Option<NonZeroUsize>; 11],
    setup_wait: Option<Duration>,
}

pub(super) fn parse(value: Option<&Bound<'_, PyAny>>) -> PyResult<Pool> {
    let Some(value) = value else {
        return Ok(Pool::default());
    };
    let mut pool = Pool::default();
    for (index, name) in COUNT_FIELDS.iter().enumerate() {
        let value = value
            .getattr(*name)
            .map_err(|_| error::input("invalid_pool"))?;
        if !value.is_none() {
            let count = value
                .cast_exact::<PyInt>()
                .map_err(|_| error::input(name))?
                .extract::<usize>()
                .map_err(|_| error::input(name))?;
            pool.counts[index] = Some(NonZeroUsize::new(count).ok_or_else(|| error::input(name))?);
        }
    }
    let value = value
        .getattr("negotiated_setup_wait_limit")
        .map_err(|_| error::input("invalid_pool"))?;
    if !value.is_none() {
        let name = "negotiated_setup_wait_limit";
        if value.cast_exact::<PyInt>().is_err() && value.cast_exact::<PyFloat>().is_err() {
            return Err(error::input(name));
        }
        let seconds = value.extract::<f64>().map_err(|_| error::input(name))?;
        pool.setup_wait =
            Some(Duration::try_from_secs_f64(seconds).map_err(|_| error::input(name))?);
    }
    Ok(pool)
}

impl Pool {
    pub(super) fn apply(self, mut builder: ClientBuilder) -> ClientBuilder {
        if let Some(maximum) = self.counts[0] {
            builder = builder.max_retained_http1_connections(maximum);
        }
        if let Some(maximum) = self.counts[1] {
            builder = builder.max_concurrent_http1_requests_per_origin(maximum);
        }
        if let Some(maximum) = self.counts[2] {
            builder = builder.max_pending_http1_requests_per_origin(maximum);
        }
        if let Some(maximum) = self.counts[3] {
            builder = builder.max_retained_http2_connections(maximum);
        }
        if let Some(maximum) = self.counts[4] {
            builder = builder.max_concurrent_http2_requests_per_origin(maximum);
        }
        if let Some(maximum) = self.counts[5] {
            builder = builder.max_pending_http2_requests_per_origin(maximum);
        }
        if let Some(maximum) = self.counts[6] {
            builder = builder.max_http2_connections_per_origin(maximum);
        }
        if let Some(maximum) = self.counts[7] {
            builder = builder.max_retained_http3_connections(maximum);
        }
        if let Some(maximum) = self.counts[8] {
            builder = builder.max_concurrent_http3_requests_per_origin(maximum);
        }
        if let Some(maximum) = self.counts[9] {
            builder = builder.max_pending_http3_requests_per_origin(maximum);
        }
        if let Some(maximum) = self.counts[10] {
            builder = builder.max_http3_connections_per_origin(maximum);
        }
        if let Some(limit) = self.setup_wait {
            builder = builder.negotiated_setup_wait_limit(limit);
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_counts_and_duration_reject_coercion_and_keep_omission() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let scope = pyo3::types::PyDict::new(py);
            py.run(
                c"from types import SimpleNamespace
def pool(**changes):
    values = dict(max_retained_http1_connections=None,
        max_concurrent_http1_requests_per_origin=None,
        max_pending_http1_requests_per_origin=None,
        max_retained_http2_connections=None,
        max_concurrent_http2_requests_per_origin=None,
        max_pending_http2_requests_per_origin=None,
        max_http2_connections_per_origin=None,
        max_retained_http3_connections=None,
        max_concurrent_http3_requests_per_origin=None,
        max_pending_http3_requests_per_origin=None,
        max_http3_connections_per_origin=None,
        negotiated_setup_wait_limit=None)
    values.update(changes)
    return SimpleNamespace(**values)
class Coerce:
    def __index__(self): raise ValueError('private')
    def __float__(self): raise ValueError('private')
class Subclass(int): pass
class FloatSubclass(float): pass
class Raising:
    @property
    def max_retained_http1_connections(self): raise ValueError('private')
",
                Some(&scope),
                None,
            )?;
            for source in [
                c"pool()",
                c"pool(max_retained_http1_connections=1, negotiated_setup_wait_limit=0)",
                c"pool(max_retained_http1_connections=1, negotiated_setup_wait_limit=0.000000001)",
            ] {
                let value = py.eval(source, Some(&scope), None)?;
                let pool = parse(Some(&value))?;
                if !value.getattr("max_retained_http1_connections")?.is_none() {
                    assert_eq!(pool.counts[0].map(NonZeroUsize::get), Some(1));
                    assert!(pool.setup_wait.is_some());
                } else {
                    assert!(pool.counts.iter().all(Option::is_none));
                    assert!(pool.setup_wait.is_none());
                }
            }
            for source in [
                c"object()",
                c"SimpleNamespace()",
                c"Raising()",
                c"pool(max_retained_http1_connections=True)",
                c"pool(max_retained_http1_connections=0)",
                c"pool(max_retained_http1_connections=-1)",
                c"pool(max_retained_http1_connections=1 << 128)",
                c"pool(max_retained_http1_connections=1.0)",
                c"pool(max_retained_http1_connections=Coerce())",
                c"pool(max_retained_http1_connections=Subclass(1))",
                c"pool(negotiated_setup_wait_limit=True)",
                c"pool(negotiated_setup_wait_limit=FloatSubclass(1))",
                c"pool(negotiated_setup_wait_limit=float('nan'))",
                c"pool(negotiated_setup_wait_limit=float('inf'))",
                c"pool(negotiated_setup_wait_limit=-1)",
                c"pool(negotiated_setup_wait_limit=1 << 128)",
                c"pool(negotiated_setup_wait_limit=Coerce())",
            ] {
                let value = py.eval(source, Some(&scope), None)?;
                let failure = parse(Some(&value))
                    .err()
                    .ok_or_else(|| error::input("test_expected_pool_error"))?;
                let args: (String, String, Option<String>, Option<String>) =
                    failure.value(py).getattr("args")?.extract()?;
                assert_eq!(args.0, "input");
                assert!(!args.1.contains("private"));
            }
            Ok(())
        })
    }

    #[test]
    fn named_pool_fields_are_read_once_and_apply_to_their_own_count() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let scope = pyo3::types::PyDict::new(py);
            py.run(
                c"class Settings:
    def __init__(self):
        self.reads = {}
        self.values = dict(max_retained_http1_connections=1,
            max_concurrent_http1_requests_per_origin=2,
            max_pending_http1_requests_per_origin=3,
            max_retained_http2_connections=4,
            max_concurrent_http2_requests_per_origin=5,
            max_pending_http2_requests_per_origin=6,
            max_http2_connections_per_origin=7,
            max_retained_http3_connections=8,
            max_concurrent_http3_requests_per_origin=9,
            max_pending_http3_requests_per_origin=10,
            max_http3_connections_per_origin=11,
            negotiated_setup_wait_limit=0)
    def __getattr__(self, name):
        self.reads[name] = self.reads.get(name, 0) + 1
        if self.reads[name] != 1: raise ValueError('private')
        return self.values[name]
settings = Settings()
",
                Some(&scope),
                None,
            )?;
            let value = scope
                .get_item("settings")?
                .ok_or_else(|| error::input("test_settings"))?;
            let pool = parse(Some(&value))?;
            assert_eq!(
                pool.counts.map(|count| count.map(NonZeroUsize::get)),
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map(Some)
            );
            assert_eq!(pool.setup_wait, Some(Duration::ZERO));
            assert!(py.eval(c"len(settings.reads) == 12 and all(value == 1 for value in settings.reads.values())", Some(&scope), None)?.is_truthy()?);
            Ok(())
        })
    }
}
