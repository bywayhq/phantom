//! Recovery from rejected socket tuning, separate from socket setup and I/O.

use std::io;

use phantom_profile::SocketOptionPolicy;

pub(crate) fn apply(
    policy: SocketOptionPolicy,
    option: &'static str,
    result: io::Result<()>,
) -> io::Result<()> {
    match (policy, result) {
        (SocketOptionPolicy::BestEffort, Err(error)) => {
            tracing::debug!(option, %error, "socket tuning rejected");
            Ok(())
        }
        (_, result) => result,
    }
}
