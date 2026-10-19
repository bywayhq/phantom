//! Native Python adapter using the public asynchronous client.

use pyo3::prelude::*;

mod client;
mod error;
mod response;
mod runtime;
mod upload;

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<client::NativeClient>()?;
    module.add_class::<client::AttemptBudget>()?;
    module.add_class::<client::NativeCookies>()?;
    module.add_class::<response::NativeResponse>()?;
    module.add("NativeError", module.py().get_type::<error::NativeError>())?;
    Ok(())
}
