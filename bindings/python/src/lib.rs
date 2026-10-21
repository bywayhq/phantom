//! Native Python adapter using the public asynchronous client.

use pyo3::prelude::*;

mod client;
mod client_certificate;
mod configuration;
mod diagnostics;
mod error;
mod network;
mod pool;
mod prepared_body;
mod profile;
mod request_fields;
mod response;
mod runtime;
mod session;
mod streaming_multipart;
mod transfer;
mod upload;

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<client::NativeClient>()?;
    module.add_class::<client_certificate::NativeClientCertificate>()?;
    module.add_class::<diagnostics::NativeRequestDiagnostics>()?;
    module.add_class::<client::AttemptBudget>()?;
    module.add_class::<transfer::NativeTransferControl>()?;
    module.add_class::<client::NativeCookies>()?;
    module.add_class::<response::NativeResponse>()?;
    module.add_class::<upload::NativeUpload>()?;
    module.add_class::<streaming_multipart::NativeStreamingMultipart>()?;
    module.add_class::<profile::NativeProfile>()?;
    module.add_class::<prepared_body::NativePreparedBody>()?;
    module.add(
        "NativeProfileError",
        module.py().get_type::<profile::NativeProfileError>(),
    )?;
    module.add("NativeError", module.py().get_type::<error::NativeError>())?;
    Ok(())
}
