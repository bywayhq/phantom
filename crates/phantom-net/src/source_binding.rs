//! Binding outgoing sockets to a local address or a network interface.
//!
//! A [`SourceBinding`] is a caller option, not part of any browser recipe:
//! without one, every socket keeps the operating system's choice of source
//! address and interface. Each platform binds an interface with its own
//! socket option, set before the socket binds an address or connects:
//!
//! | Platform | Option | Name |
//! | --- | --- | --- |
//! | Linux, Android | `SO_BINDTODEVICE` | Up to 15 bytes, such as `eth0` |
//! | macOS | `IP_BOUND_IF`, `IPV6_BOUND_IF` | Up to 15 bytes, such as `en0` |
//! | Windows | `IP_UNICAST_IF`, `IPV6_UNICAST_IF` | An alias, such as `Ethernet`, or an NDIS name, such as `ethernet_32768`; up to 256 UTF-16 code units |
//!
//! macOS and Windows take an interface index, which each socket looks up
//! from the name when it binds, so a name no interface has fails that
//! socket with [`io::ErrorKind::NotFound`]. The macOS code also compiles for
//! iOS and the other Apple platforms, where no test runs it.

use std::{
    error::Error,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use socket2::{Domain, SockRef};
use tokio::net::TcpSocket;

/// Whether this platform can bind a socket to an interface by name.
const INTERFACE_BINDING: bool = cfg!(any(
    target_os = "android",
    target_os = "linux",
    target_vendor = "apple",
    windows
));

/// This platform's limit on the length of an interface name.
const INTERFACE_NAME_LIMIT: InterfaceNameLimit = if cfg!(windows) {
    InterfaceNameLimit::IfMaxStringSize
} else {
    InterfaceNameLimit::Ifnamsiz
};

/// A platform's limit on the length of an interface name, without its
/// terminating NUL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InterfaceNameLimit {
    /// `IFNAMSIZ`, 16 bytes on Linux, Android, and Apple platforms, holds 15
    /// bytes and the NUL.
    Ifnamsiz,
    /// Windows' `IF_MAX_STRING_SIZE`: 256 UTF-16 code units, for an interface
    /// alias or NDIS name.
    IfMaxStringSize,
}

impl InterfaceNameLimit {
    /// Checks that `name` is not empty, holds no NUL, and fits this limit.
    fn check(self, name: &str) -> Result<(), InvalidSourceBinding> {
        let (length, maximum, message) = match self {
            Self::Ifnamsiz => (
                name.len(),
                15,
                "an interface name must be 1 to 15 bytes without NUL",
            ),
            Self::IfMaxStringSize => (
                name.encode_utf16().count(),
                256,
                "an interface name must be 1 to 256 UTF-16 code units without NUL",
            ),
        };
        if length == 0 || length > maximum || name.contains('\0') {
            return Err(InvalidSourceBinding::new("interface", message));
        }
        Ok(())
    }
}

/// The local address, per address family, and the network interface that
/// outgoing TCP and UDP sockets bind to before they connect or send.
///
/// Each family has its own address, as curl's `--interface` and hyper-util's
/// `HttpConnector::set_local_addresses` do, because one socket can bind only an
/// address of its own family. When the binding names an address for one family
/// only, the addresses of the other family are skipped: a host that resolves to
/// both is reached over the bound family, and one that resolves only to the
/// other family fails with [`io::ErrorKind::AddrNotAvailable`] instead of
/// leaving from an unbound socket. A binding with no address leaves the source
/// address to the operating system.
///
/// An interface name binds each socket to that interface before the socket
/// binds an address or connects, on Linux, Android, macOS, and Windows, with
/// the options the [module documentation](self) lists;
/// elsewhere [`Self::validate`] rejects it. On Windows the option chooses
/// the interface of the socket's outgoing unicast packets only, and does not
/// filter what the socket receives. An address set alongside the interface
/// must belong to that interface; Phantom does not check that the two agree.
/// Name resolution is not bound.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct SourceBinding {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    interface: Option<Box<str>>,
}

impl SourceBinding {
    /// Returns a binding with no address and no interface.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ipv4: None,
            ipv6: None,
            interface: None,
        }
    }

    /// Binds sockets of `address`'s family to `address`, replacing any
    /// earlier address of that family.
    #[must_use]
    pub fn with_address(mut self, address: IpAddr) -> Self {
        match address {
            IpAddr::V4(address) => self.ipv4 = Some(address),
            IpAddr::V6(address) => self.ipv6 = Some(address),
        }
        self
    }

    /// Binds every socket to the network interface named `name`.
    #[must_use]
    pub fn with_interface(mut self, name: impl Into<Box<str>>) -> Self {
        self.interface = Some(name.into());
        self
    }

    /// Returns the local IPv4 address, if any.
    #[must_use]
    pub const fn ipv4_address(&self) -> Option<Ipv4Addr> {
        self.ipv4
    }

    /// Returns the local IPv6 address, if any.
    #[must_use]
    pub const fn ipv6_address(&self) -> Option<Ipv6Addr> {
        self.ipv6
    }

    /// Returns the interface name, if any.
    #[must_use]
    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Checks that a socket can bind as this binding says, without I/O.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSourceBinding`] when an address is unspecified,
    /// multicast, or the IPv4 broadcast address; when the interface name is
    /// empty, holds a NUL byte, or is longer than 15 bytes (256 UTF-16 code
    /// units on Windows); or when this platform cannot bind a socket to an
    /// interface by name.
    pub fn validate(&self) -> Result<(), InvalidSourceBinding> {
        if let Some(address) = self.ipv4
            && (address.is_unspecified() || address.is_multicast() || address.is_broadcast())
        {
            return Err(InvalidSourceBinding::new(
                "ipv4_address",
                "a source address must be a unicast address",
            ));
        }
        if let Some(address) = self.ipv6
            && (address.is_unspecified() || address.is_multicast())
        {
            return Err(InvalidSourceBinding::new(
                "ipv6_address",
                "a source address must be a unicast address",
            ));
        }
        if let Some(name) = &self.interface {
            INTERFACE_NAME_LIMIT.check(name)?;
            if !INTERFACE_BINDING {
                return Err(InvalidSourceBinding::new(
                    "interface",
                    "this platform cannot bind a socket to an interface by name",
                ));
            }
        }
        Ok(())
    }

    /// Returns whether a socket to `remote` can bind as this binding says.
    pub(crate) const fn permits(&self, remote: &SocketAddr) -> bool {
        if self.ipv4.is_none() && self.ipv6.is_none() {
            return true;
        }
        match remote {
            SocketAddr::V4(_) => self.ipv4.is_some(),
            SocketAddr::V6(_) => self.ipv6.is_some(),
        }
    }

    /// Keeps the addresses this binding permits, in order.
    ///
    /// # Errors
    ///
    /// Fails with [`io::ErrorKind::AddrNotAvailable`] when `addresses` is not
    /// empty but none of them has a family with a source address.
    pub(crate) fn usable_addresses(
        &self,
        addresses: Vec<SocketAddr>,
    ) -> io::Result<Vec<SocketAddr>> {
        if addresses.is_empty() {
            return Ok(addresses);
        }
        let usable: Vec<_> = addresses
            .into_iter()
            .filter(|address| self.permits(address))
            .collect();
        if usable.is_empty() {
            return Err(no_bound_family());
        }
        Ok(usable)
    }

    /// Returns the source address for a socket to `remote`, if the binding
    /// names one for its family.
    const fn address_for(&self, remote: &SocketAddr) -> Option<IpAddr> {
        match remote {
            SocketAddr::V4(_) => match self.ipv4 {
                Some(address) => Some(IpAddr::V4(address)),
                None => None,
            },
            SocketAddr::V6(_) => match self.ipv6 {
                Some(address) => Some(IpAddr::V6(address)),
                None => None,
            },
        }
    }

    /// Binds a TCP socket that will connect to `remote`.
    pub(crate) fn bind_tcp(&self, socket: &TcpSocket, remote: SocketAddr) -> io::Result<()> {
        if !self.permits(&remote) {
            return Err(no_bound_family());
        }
        self.bind_interface(&SockRef::from(socket), Domain::for_address(remote))?;
        match self.address_for(&remote) {
            Some(address) => socket
                .bind(SocketAddr::new(address, 0))
                .map_err(|error| bind_error("TCP", address, error)),
            None => Ok(()),
        }
    }

    /// Returns the local address of a UDP socket that sends to `remote`: this
    /// binding's address for its family, or `default_local` when it has none.
    pub(crate) fn udp_local_address(
        &self,
        remote: SocketAddr,
        default_local: SocketAddr,
    ) -> io::Result<SocketAddr> {
        if !self.permits(&remote) {
            return Err(no_bound_family());
        }
        Ok(self
            .address_for(&remote)
            .map_or(default_local, |address| SocketAddr::new(address, 0)))
    }

    /// Binds `socket`, of family `domain`, to this binding's interface with
    /// `SO_BINDTODEVICE`, if the binding names one.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub(crate) fn bind_interface(&self, socket: &SockRef<'_>, _domain: Domain) -> io::Result<()> {
        let Some(name) = &self.interface else {
            return Ok(());
        };
        socket
            .bind_device(Some(name.as_bytes()))
            .map_err(|error| interface_error(name, error))
    }

    /// Binds `socket`, of family `domain`, to this binding's interface with
    /// `IP_BOUND_IF` or `IPV6_BOUND_IF`, if the binding names one.
    #[cfg(target_vendor = "apple")]
    pub(crate) fn bind_interface(&self, socket: &SockRef<'_>, domain: Domain) -> io::Result<()> {
        let Some(name) = &self.interface else {
            return Ok(());
        };
        bind_to_interface_index(socket, name, domain).map_err(|error| interface_error(name, error))
    }

    /// Binds `socket`, of family `domain`, to this binding's interface with
    /// `IP_UNICAST_IF` or `IPV6_UNICAST_IF`, if the binding names one.
    #[cfg(windows)]
    pub(crate) fn bind_interface(&self, socket: &SockRef<'_>, domain: Domain) -> io::Result<()> {
        use std::os::windows::io::AsSocket;

        let Some(name) = &self.interface else {
            return Ok(());
        };
        crate::socket_ffi::interface::index(name)
            .and_then(|index| {
                crate::socket_ffi::interface::set_unicast_interface(
                    socket.as_socket(),
                    domain,
                    index,
                )
            })
            .map_err(|error| interface_error(name, error))
    }

    /// Fails when the binding names an interface: this platform cannot bind
    /// a socket to one by name.
    #[cfg(not(any(
        target_os = "android",
        target_os = "linux",
        target_vendor = "apple",
        windows
    )))]
    pub(crate) fn bind_interface(&self, _socket: &SockRef<'_>, _domain: Domain) -> io::Result<()> {
        match &self.interface {
            None => Ok(()),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this platform cannot bind a socket to an interface by name",
            )),
        }
    }
}

/// Binds `socket` to the interface named `name` by its index, with
/// `IP_BOUND_IF` or `IPV6_BOUND_IF` as socket2 sets them on Apple platforms.
///
/// Linux and Android test builds compile this too, where socket2 sets
/// `SO_BINDTOIFINDEX` for both families, so that the Apple path is
/// type-checked and run off Apple hosts. Their production builds bind by
/// name instead and never compile it.
#[cfg(any(
    target_vendor = "apple",
    all(test, any(target_os = "android", target_os = "linux"))
))]
fn bind_to_interface_index(socket: &SockRef<'_>, name: &str, domain: Domain) -> io::Result<()> {
    let index = Some(crate::socket_ffi::interface::index(name)?);
    if domain == Domain::IPV6 {
        socket.bind_device_by_index_v6(index)
    } else {
        socket.bind_device_by_index_v4(index)
    }
}

/// Encodes interface `index` as the value of Windows' `IP_UNICAST_IF` for an
/// IPv4 socket, in network byte order, or of `IPV6_UNICAST_IF` for an IPv6
/// socket, in host byte order, as Microsoft's `IPPROTO_IP` and
/// `IPPROTO_IPV6` socket option references specify.
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "only Windows sets the option; tests check the encoding everywhere"
    )
)]
pub(crate) fn unicast_interface_value(index: u32, domain: Domain) -> [u8; 4] {
    if domain == Domain::IPV6 {
        index.to_ne_bytes()
    } else {
        index.to_be_bytes()
    }
}

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_vendor = "apple",
    windows
))]
fn interface_error(name: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("failed to bind a socket to interface {name:?}: {error}"),
    )
}

fn no_bound_family() -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no resolved address has a family the source binding has an address for",
    )
}

pub(crate) fn bind_error(protocol: &str, address: IpAddr, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("failed to bind a {protocol} socket to source address {address}: {error}"),
    )
}

/// Error returned when a [`SourceBinding`] cannot be applied as written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidSourceBinding {
    field: &'static str,
    message: &'static str,
}

impl InvalidSourceBinding {
    const fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }

    /// Returns the rejected field: `ipv4_address`, `ipv6_address`, or
    /// `interface`.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for InvalidSourceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid source binding {}: {}",
            self.field, self.message
        )
    }
}

impl Error for InvalidSourceBinding {}

#[cfg(test)]
mod tests;
