//! Native Go adapter using Phantom's public asynchronous client.

mod client;
mod client_certificate;
mod error;
#[allow(unsafe_code)]
mod ffi;
mod operations;
mod policy;
mod prepared_body;
mod profile;
mod retry;
mod session;
mod timeouts;
mod upload;
