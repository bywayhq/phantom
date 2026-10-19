use std::sync::OnceLock;

use pyo3::{exceptions::PyRuntimeError, prelude::*};

pub(super) fn initialize() -> PyResult<()> {
    static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| "could not start the HTTP runtime".to_owned())
    });
    let runtime = runtime
        .as_ref()
        .map_err(|message| PyRuntimeError::new_err(message.clone()))?;
    if !*INSTALLED.get_or_init(|| pyo3_async_runtimes::tokio::init_with_runtime(runtime).is_ok()) {
        return Err(PyRuntimeError::new_err(
            "HTTP runtime was already initialized externally",
        ));
    }
    Ok(())
}
