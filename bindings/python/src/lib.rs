//! Native Python adapter using the public asynchronous client.

use pyo3::prelude::*;

mod client;
mod configuration;
mod error;
mod profile;
mod response;
mod runtime;
mod session;
mod upload;

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<client::NativeClient>()?;
    module.add_class::<client::AttemptBudget>()?;
    module.add_class::<client::NativeCookies>()?;
    module.add_class::<response::NativeResponse>()?;
    module.add_class::<upload::NativeUpload>()?;
    module.add_class::<profile::NativeProfile>()?;
    module.add(
        "NativeProfileError",
        module.py().get_type::<profile::NativeProfileError>(),
    )?;
    module.add("NativeError", module.py().get_type::<error::NativeError>())?;
    Ok(())
}
