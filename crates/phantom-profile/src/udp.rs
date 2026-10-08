//! Socket options for QUIC and Phantom's own DNS queries.

/// Socket options for QUIC and Phantom's own DNS queries.
///
/// A value applies to the socket of every QUIC connection, to an origin or
/// to a CONNECT-UDP proxy, and to the UDP socket of a SOCKS5 UDP
/// association. The client also applies it to address and HTTPS-record
/// UDP query sockets that Phantom opens. DNS sockets opened by the operating
/// system are unaffected. A field that asks for nothing leaves the socket
/// at its operating-system default. [`Self::default`] asks for nothing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UdpSettings {
    /// Whether to ask Windows for a random local port with
    /// `SO_RANDOMIZE_PORT`, rather than the next free port in sequence.
    ///
    /// A server sees the difference in the source ports of successive
    /// sockets. Windows rejects the option on a socket that is already bound,
    /// so it is set first, before the socket binds, with or without a source
    /// binding. A rejection fails the connection attempt.
    ///
    /// Only Windows has the option. Elsewhere the setting changes nothing.
    pub port_randomization: bool,
}
