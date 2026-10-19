//! Redacted failures for the JavaScript adapter.

use napi::{Error, Status};

pub(crate) fn failure(code: &str, message: &str) -> Error {
    // The JS facade turns this private transport prefix into PhantomError.code.
    Error::new(Status::GenericFailure, format!("PHANTOM:{code}:{message}"))
}

pub(crate) fn request(error: phantom::RequestError) -> Error {
    failure(&format!("{:?}", error.kind()), &error.to_string())
}
