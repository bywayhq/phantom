//! Explicit pool overrides owned before client construction.

use std::{num::NonZeroUsize, time::Duration};

use phantom::ClientBuilder;
use pyo3::{
    prelude::*,
    types::{PyFloat, PyInt, PyTuple},
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
    let fields = value
        .cast_exact::<PyTuple>()
        .map_err(|_| error::input("invalid_pool"))?;
    if fields.len() != 12 {
        return Err(error::input("invalid_pool"));
    }
    let mut pool = Pool::default();
    for (index, name) in COUNT_FIELDS.iter().enumerate() {
        let value = fields.get_item(index)?;
        if !value.is_none() {
            let count = value
                .cast_exact::<PyInt>()
                .map_err(|_| error::input(name))?
                .extract::<usize>()
                .map_err(|_| error::input(name))?;
            pool.counts[index] = Some(NonZeroUsize::new(count).ok_or_else(|| error::input(name))?);
        }
    }
    let value = fields.get_item(11)?;
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
            for source in [
                c"(None,) * 12",
                c"(1,) * 11 + (0,)",
                c"(1,) * 11 + (0.000000001,)",
            ] {
                let value = py.eval(source, None, None)?;
                let pool = parse(Some(&value))?;
                if !value.get_item(0)?.is_none() {
                    assert_eq!(pool.counts[0].map(NonZeroUsize::get), Some(1));
                    assert!(pool.setup_wait.is_some());
                }
            }
            let scope = pyo3::types::PyDict::new(py);
            py.run(c"class Coerce:\n    def __index__(self): raise ValueError('private')\n    def __float__(self): raise ValueError('private')\nclass Subclass(int): pass\n", Some(&scope), None)?;
            for source in [
                c"[]",
                c"(None,) * 11",
                c"(True,) + (None,) * 11",
                c"(0,) + (None,) * 11",
                c"(-1,) + (None,) * 11",
                c"(1 << 128,) + (None,) * 11",
                c"(1.0,) + (None,) * 11",
                c"(Coerce(),) + (None,) * 11",
                c"(Subclass(1),) + (None,) * 11",
                c"(None,) * 11 + (True,)",
                c"(None,) * 11 + (float('nan'),)",
                c"(None,) * 11 + (float('inf'),)",
                c"(None,) * 11 + (-1,)",
                c"(None,) * 11 + (1 << 128,)",
                c"(None,) * 11 + (Coerce(),)",
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
}
