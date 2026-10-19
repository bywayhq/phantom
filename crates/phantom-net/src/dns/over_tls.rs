//! Verified DNS messages on one reusable, multiplexed TLS connection.

use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    time::Duration,
};

use hickory_resolver::{
    net::{
        DnsHandle, DnsMultiplexer, NetError,
        runtime::{TokioRuntimeProvider, iocompat::AsyncIoTokioAsStd},
        tcp::{TcpClientStream, TcpStream},
        xfer::{DnsExchange, FirstAnswer},
    },
    proto::op::{DnsRequest, DnsRequestOptions, Message},
};
use phantom_profile::TlsSettings;
use tokio::{
    net::TcpSocket,
    sync::{Mutex, Semaphore},
    task::JoinHandle,
};

use super::wire::{DnsWireErrorKind, DnsWireQuery, DnsWireResult};
use crate::tls::TlsConnector;

#[cfg(test)]
mod tests;

/// A direct, authenticated DNS-over-TLS transport for encoded DNS questions.
///
/// Clones share one connection and its query limit. Bootstrap addresses are
/// supplied by the caller; no OS DNS, proxy, cleartext fallback or DNSSEC
/// validation is used. The supplied TLS settings offer `dot`, omit ALPS and
/// disable early data. This is not a captured browser DNS recipe.
#[derive(Clone)]
pub struct DnsOverTlsTransport {
    endpoint: Arc<Endpoint>,
}

struct Endpoint {
    name: String,
    bootstrap: Box<[SocketAddr]>,
    tls: TlsConnector,
    timeout: Duration,
    maximum_queries: usize,
    admission: Semaphore,
    connection: Mutex<Option<Arc<Connection>>>,
}

struct Connection {
    exchange: DnsExchange<TokioRuntimeProvider>,
    driver: JoinHandle<()>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl fmt::Debug for DnsOverTlsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsOverTlsTransport")
            .field("bootstrap_addresses", &self.endpoint.bootstrap.len())
            .field("query_timeout", &self.endpoint.timeout)
            .field("maximum_queries", &self.endpoint.maximum_queries)
            .finish_non_exhaustive()
    }
}

impl DnsOverTlsTransport {
    /// Prepares a verified endpoint without opening a connection.
    ///
    /// `name` is its ASCII authentication hostname or IP literal. Addresses
    /// retain their order. An IP identity requires matching bootstrap IPs.
    /// Use port 853 normally; explicit nonzero ports are allowed.
    /// The finite timeout includes setup and the reply. At most 65535 queries
    /// can be admitted at once, including work waiting for setup.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for invalid identity, bootstrap, limits or TLS
    /// settings. TLS construction failures remain in the error's source.
    pub fn new(
        settings: &TlsSettings,
        name: &str,
        bootstrap: impl IntoIterator<Item = SocketAddr>,
        query_timeout: Duration,
        maximum_queries: NonZeroUsize,
    ) -> io::Result<Self> {
        Self::new_with_additional_roots(
            settings,
            name,
            bootstrap,
            query_timeout,
            maximum_queries,
            std::iter::empty(),
        )
    }

    /// Prepares an endpoint with additional DER public trust roots.
    ///
    /// The normal public roots and hostname verification remain enabled.
    /// Other arguments and failures are those of [`Self::new`].
    ///
    /// # Errors
    ///
    /// Also returns `InvalidInput` when a trust root cannot be loaded.
    pub fn new_with_additional_roots<'a>(
        settings: &TlsSettings,
        name: &str,
        bootstrap: impl IntoIterator<Item = SocketAddr>,
        query_timeout: Duration,
        maximum_queries: NonZeroUsize,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> io::Result<Self> {
        let name = authentication_name(name)?;
        let bootstrap: Box<[_]> = bootstrap.into_iter().collect();
        let literal = name.parse::<IpAddr>().ok();
        if bootstrap.is_empty() || bootstrap.iter().any(|address| {
            address.port() == 0
                || address.ip().is_unspecified() || address.ip().is_multicast()
                || literal.is_some_and(|literal| literal != address.ip())
                || matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
                || matches!(address, SocketAddr::V6(ip) if ip.ip().is_unicast_link_local() && ip.scope_id() == 0)
        }) {
            return Err(invalid("invalid DNS-over-TLS bootstrap addresses"));
        }
        if query_timeout.is_zero()
            || tokio::time::Instant::now()
                .checked_add(query_timeout)
                .is_none()
            || maximum_queries.get() > usize::from(u16::MAX)
        {
            return Err(invalid("invalid DNS-over-TLS query limits"));
        }
        let mut settings = settings.clone();
        settings.alpn_protocols = vec![Box::from(&b"dot"[..])];
        settings.alps = None;
        settings.tcp_early_data = false;
        let tls = TlsConnector::new_with_additional_roots(&settings, roots)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            endpoint: Arc::new(Endpoint {
                name,
                bootstrap,
                tls,
                timeout: query_timeout,
                maximum_queries: maximum_queries.get(),
                admission: Semaphore::new(maximum_queries.get()),
                connection: Mutex::new(None),
            }),
        })
    }

    /// Sends one question and validates its correlated DNS response.
    ///
    /// The transport assigns an unused message ID. Questions may complete
    /// out of order. Cancellation drops this query's interest without closing
    /// the shared connection. Its pending protocol work retains a finite
    /// timeout. A later query reconnects after a connection failure.
    ///
    /// # Errors
    ///
    /// Returns `WouldBlock` when admission is full, `TimedOut` at the deadline,
    /// `InvalidData` for a decoded answer that fails validation, or an I/O/TLS
    /// failure with its source. Unreadable replies and unknown IDs may instead
    /// expire at the deadline. A Tokio runtime with I/O and time is required.
    pub async fn exchange(&self, query: &DnsWireQuery) -> io::Result<DnsWireResult> {
        let _permit = self.endpoint.admission.try_acquire().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "DNS-over-TLS query admission is full",
            )
        })?;
        tokio::runtime::Handle::try_current().map_err(|_| runtime_unavailable())?;
        // Tokio exposes no time-driver query. Construct only this timer under
        // the guard, after validating its clock range above.
        let timer = catch_unwind(AssertUnwindSafe(|| {
            tokio::time::sleep(self.endpoint.timeout)
        }))
        .map_err(|_| runtime_unavailable())?;
        tokio::pin!(timer);
        tokio::select! {
            result = crate::direct::poll_tokio_io(|| self.endpoint.exchange(query)) => {
                result.map_err(|_| runtime_unavailable())?
            }
            () = &mut timer => Err(io::Error::new(io::ErrorKind::TimedOut, "DNS-over-TLS query deadline expired")),
        }
    }
}

impl Endpoint {
    async fn exchange(&self, query: &DnsWireQuery) -> io::Result<DnsWireResult> {
        let connection = self.connection().await?;
        let message = Message::from_vec(query.as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let result = connection
            .exchange
            .send(DnsRequest::new(message, DnsRequestOptions::default()))
            .first_answer()
            .await;
        match result {
            Ok(response) => query
                .parse_multiplexed_response(response.id, response.as_buffer())
                .map_err(|error| {
                    let kind = if error.kind() == DnsWireErrorKind::Server {
                        io::ErrorKind::Other
                    } else {
                        io::ErrorKind::InvalidData
                    };
                    io::Error::new(kind, error)
                }),
            Err(error) => {
                // A single cancelled/expired question must not evict a usable
                // connection. A stopped driver is replaced by connection().
                let kind = match error {
                    NetError::Timeout => io::ErrorKind::TimedOut,
                    NetError::Busy => io::ErrorKind::WouldBlock,
                    _ => io::ErrorKind::Other,
                };
                Err(io::Error::new(kind, error))
            }
        }
    }

    async fn connection(&self) -> io::Result<Arc<Connection>> {
        let mut cached = self.connection.lock().await;
        if let Some(connection) = cached
            .as_ref()
            .filter(|connection| !connection.driver.is_finished())
        {
            return Ok(Arc::clone(connection));
        }
        *cached = None;
        let mut last_error = None;
        for address in &self.bootstrap {
            match self.connect(*address).await {
                Ok(connection) => {
                    let connection = Arc::new(connection);
                    *cached = Some(Arc::clone(&connection));
                    return Ok(connection);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| invalid("missing DNS-over-TLS bootstrap")))
    }

    async fn connect(&self, address: SocketAddr) -> io::Result<Connection> {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if address.ip().is_loopback() {
            socket.bind(SocketAddr::new(address.ip(), 0))?;
        }
        socket.set_nodelay(true)?;
        let tcp = socket.connect(address).await?;
        let tls = self
            .tls
            .connect(&self.name, tcp)
            .await
            .map_err(io::Error::other)?;
        if tls.negotiated_alpn().is_some_and(|alpn| alpn != b"dot") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS-over-TLS selected another ALPN protocol",
            ));
        }
        let (stream, sender) = TcpStream::from_stream(AsyncIoTokioAsStd(tls), address);
        let multiplexer = DnsMultiplexer::new(TcpClientStream::from_stream(stream), sender)
            .with_timeout(self.timeout)
            .with_max_active_requests(self.maximum_queries);
        let (exchange, background) = DnsExchange::<TokioRuntimeProvider>::from_stream(multiplexer);
        let driver = tokio::spawn(background);
        Ok(Connection { exchange, driver })
    }
}

fn authentication_name(name: &str) -> io::Result<String> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    if name.is_empty()
        || name.len() > 253
        || !name.is_ascii()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-.".contains(&byte))
        || name.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
    {
        return Err(invalid("invalid DNS-over-TLS authentication name"));
    }
    Ok(name.to_ascii_lowercase())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn runtime_unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "DNS-over-TLS requires Tokio I/O and time drivers",
    )
}
