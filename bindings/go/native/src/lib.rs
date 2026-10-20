//! Native Go adapter using Phantom's public asynchronous client.

mod client;
mod error;
#[allow(unsafe_code)]
mod ffi;
mod operations;
mod profile;
mod timeouts;
