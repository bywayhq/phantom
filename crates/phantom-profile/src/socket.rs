/// What happens when the operating system rejects socket tuning.
///
/// This covers Nagle, buffer, keepalive and port-randomization options. It
/// never relaxes source/interface binding, input validation, DNS source-port
/// randomness or socket I/O.
///
/// ```
/// use phantom_profile::{SocketOptionPolicy, browser::chrome};
/// let mut tcp = chrome::v154_tcp();
/// tcp.option_policy = SocketOptionPolicy::Required;
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SocketOptionPolicy {
    /// Return the option error. This is the default for custom settings.
    #[default]
    Required,
    /// Report the rejection through tracing and continue the connection.
    BestEffort,
}
