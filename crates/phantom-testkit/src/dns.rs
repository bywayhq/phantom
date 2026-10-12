//! A scripted loopback DNS responder that records every query it receives.
//!
//! It answers over UDP only, which suffices for responses that fit in 512
//! bytes, and it echoes each question so resolvers accept the response.

use std::{
    error::Error,
    fmt, io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::oneshot,
    task::{JoinError, JoinHandle, JoinSet},
    time::{error::Elapsed, timeout},
};

const HEADER_LENGTH: usize = 12;
const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const RCODE_SERVFAIL: u16 = 2;
const TYPE_SOA: u16 = 6;
const CLASS_IN: u16 = 1;
const FINISH_TIMEOUT: Duration = Duration::from_secs(5);

/// One DNS query exactly as received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuery {
    wire: Vec<u8>,
    name: String,
    question_end: usize,
}

impl DnsQuery {
    fn parse(wire: &[u8]) -> Option<Self> {
        let mut offset = HEADER_LENGTH;
        let mut labels = Vec::new();
        loop {
            let length = usize::from(*wire.get(offset)?);
            offset += 1;
            if length == 0 {
                break;
            }
            if length > 63 {
                return None;
            }
            let label = wire.get(offset..offset + length)?;
            labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
            offset += length;
        }
        let question_end = offset + 4;
        if wire.len() < question_end {
            return None;
        }
        Some(Self {
            wire: wire.to_vec(),
            name: labels.join("."),
            question_end,
        })
    }

    /// Returns the whole query message.
    #[must_use]
    pub fn wire_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Returns the header flags field.
    #[must_use]
    pub fn flags(&self) -> u16 {
        self.u16_at(2)
    }

    /// Returns the header section counts: questions, answers, authority, additional.
    #[must_use]
    pub fn counts(&self) -> [u16; 4] {
        [
            self.u16_at(4),
            self.u16_at(6),
            self.u16_at(8),
            self.u16_at(10),
        ]
    }

    /// Returns the first question's name, lowercase, without the root dot.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the first question's type.
    #[must_use]
    pub fn record_type(&self) -> u16 {
        self.u16_at(self.question_end - 4)
    }

    fn u16_at(&self, offset: usize) -> u16 {
        u16::from_be_bytes([self.wire[offset], self.wire[offset + 1]])
    }
}

/// How the responder answers one query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsAnswer {
    /// Answer records of the queried type at the queried name, each with `ttl`.
    Records {
        /// Time to live of every answer record.
        ttl: u32,
        /// RDATA of each answer record, in order.
        rdata: Vec<Vec<u8>>,
    },
    /// No records of the queried type; `soa_minimum` adds an SOA authority record.
    NoData {
        /// SOA MINIMUM and TTL, from which resolvers derive the negative TTL.
        soa_minimum: Option<u32>,
    },
    /// No records of the queried type, with an SOA authority record whose
    /// record TTL and MINIMUM field differ.
    NoDataWithSoa {
        /// The SOA record's TTL.
        ttl: u32,
        /// The SOA record's MINIMUM field.
        minimum: u32,
    },
    /// A SERVFAIL response.
    ServerFailure,
    /// No response at all.
    Silence,
}

/// A scripted reply: an answer sent after an optional delay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsReply {
    answer: DnsAnswer,
    delay: Duration,
}

impl DnsReply {
    /// Replies at once.
    #[must_use]
    pub const fn new(answer: DnsAnswer) -> Self {
        Self {
            answer,
            delay: Duration::ZERO,
        }
    }

    /// Replies after `delay`; other queries are answered meanwhile.
    #[must_use]
    pub const fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

type Responder = dyn Fn(&DnsQuery) -> DnsReply + Send + Sync;

/// An original failure from a DNS receiver or reply task.
#[derive(Debug)]
pub enum DnsServerFailure {
    /// A failed socket operation or invalid scripted reply.
    Io {
        /// The operation that failed.
        operation: &'static str,
        /// The original I/O error.
        source: io::Error,
    },
    /// A reply task panicked or was cancelled before server shutdown.
    Task(JoinError),
}

impl fmt::Display for DnsServerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Task(error) => write!(formatter, "DNS reply task failed: {error}"),
        }
    }
}

impl Error for DnsServerFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Task(error) => Some(error),
        }
    }
}

/// Why observing DNS server completion failed.
#[derive(Debug)]
pub enum DnsServerError {
    /// Original receiver and reply failures, in observation order.
    Background(Vec<DnsServerFailure>),
    /// The receiver task panicked or was cancelled independently.
    Task(JoinError),
    /// The five-second completion wait expired; the server retains its task.
    Deadline(Elapsed),
}

impl fmt::Display for DnsServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Background(failures) => {
                formatter.write_str("DNS server failed")?;
                for failure in failures {
                    write!(formatter, "; {failure}")?;
                }
                Ok(())
            }
            Self::Task(error) => write!(formatter, "DNS receiver task failed: {error}"),
            Self::Deadline(error) => write!(formatter, "DNS server completion timed out: {error}"),
        }
    }
}

impl Error for DnsServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Background(failures) => failures.first().map(|error| error as &dyn Error),
            Self::Task(error) => Some(error),
            Self::Deadline(error) => Some(error),
        }
    }
}

/// A UDP DNS responder on an ephemeral IPv4 loopback port.
///
/// Dropping the server cancels its receiver and pending replies. Their socket
/// is released when the runtime polls the cancelled tasks.
pub struct DnsServer {
    address: SocketAddr,
    queries: Arc<Mutex<Vec<DnsQuery>>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Vec<DnsServerFailure>>>,
}

impl DnsServer {
    /// Binds `127.0.0.1:0` and answers each query with `responder`.
    /// Calls `responder` in query arrival order. Delayed replies run concurrently.
    /// The responder is synchronous and must return promptly without blocking
    /// the runtime.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if binding, setting nonblocking mode, registering
    /// the socket, or reading its local address fails.
    ///
    /// # Panics
    ///
    /// Panics when polled outside a Tokio runtime with I/O enabled, as
    /// [`crate::udp::bind_tokio`] and [`tokio::spawn`] do. Delayed reply tasks
    /// also require the runtime's timer to be enabled.
    pub async fn spawn(
        responder: impl Fn(&DnsQuery) -> DnsReply + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let socket = Arc::new(crate::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?);
        let address = socket.local_addr()?;
        let queries = Arc::new(Mutex::new(Vec::new()));
        let responder: Arc<Responder> = Arc::new(responder);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve(socket, Arc::clone(&queries), responder, stopped));
        Ok(Self {
            address,
            queries,
            stop: Some(stop),
            task: Some(task),
        })
    }

    /// Returns the bound address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns every well-formed query received so far, in arrival order.
    #[must_use]
    pub fn queries(&self) -> Vec<DnsQuery> {
        self.queries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Stops receiving queries, cancels unfinished replies, and collects failures.
    ///
    /// Uses a five-second timeout. Cancelling this wait or reaching its deadline
    /// leaves the original task owned by the server, so you can call it again.
    /// Returns the background outcome once. Later calls after collection succeed.
    /// The timeout is cooperative and cannot preempt a blocked responder.
    ///
    /// # Errors
    ///
    /// Returns original receiver, reply-building, send, and task failures, or the
    /// completion deadline. Deliberate silence and shutdown cancellation succeed.
    ///
    /// # Panics
    ///
    /// Panics outside a Tokio runtime with its timer enabled, as [`timeout`] does.
    pub async fn finish(&mut self) -> Result<(), DnsServerError> {
        if let Some(stop) = self.stop.take() {
            // A receiver that already finished has already closed admission.
            let _ = stop.send(());
        }
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };

        let outcome = timeout(FINISH_TIMEOUT, task)
            .await
            .map_err(DnsServerError::Deadline)?;
        drop(self.task.take());

        match outcome {
            Ok(failures) if failures.is_empty() => Ok(()),
            Ok(failures) => Err(DnsServerError::Background(failures)),
            Err(error) => Err(DnsServerError::Task(error)),
        }
    }
}

impl fmt::Debug for DnsServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsServer")
            .field("address", &self.address)
            .field(
                "task_finished",
                &self.task.as_ref().is_none_or(JoinHandle::is_finished),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn serve(
    socket: Arc<UdpSocket>,
    queries: Arc<Mutex<Vec<DnsQuery>>>,
    responder: Arc<Responder>,
    mut stopped: oneshot::Receiver<()>,
) -> Vec<DnsServerFailure> {
    let mut buffer = vec![0; 65_535];
    let mut replies = JoinSet::new();
    let mut failures = Vec::new();
    loop {
        let received = tokio::select! {
            biased;
            _ = &mut stopped => break,
            Some(outcome) = replies.join_next(), if !replies.is_empty() => {
                if let Some(error) = reply_failure(outcome, false) {
                    failures.push(error);
                    break;
                }
                continue;
            }
            received = socket.recv_from(&mut buffer) => received,
        };
        let (length, peer) = match received {
            Ok(received) => received,
            // Winsock recvfrom: UDP WSAECONNRESET reports an earlier reply's
            // ICMP Port Unreachable. Other receive failures remain errors.
            // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom
            Err(error) if cfg!(windows) && error.raw_os_error() == Some(10054) => continue,
            Err(source) => {
                failures.push(DnsServerFailure::Io {
                    operation: "receive DNS query",
                    source,
                });
                break;
            }
        };
        let Some(query) = DnsQuery::parse(&buffer[..length]) else {
            continue;
        };
        queries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(query.clone());
        let socket = Arc::clone(&socket);
        let responder = Arc::clone(&responder);
        let (called, wait_for_call) = oneshot::channel();
        replies.spawn(async move {
            let reply = responder(&query);
            if called.send(()).is_err() {
                // Admission was stopped while the responder was running.
                return Ok(());
            }

            if !reply.delay.is_zero() {
                tokio::time::sleep(reply.delay).await;
            }
            if let Some(response) =
                response(&query, &reply.answer).map_err(|source| DnsServerFailure::Io {
                    operation: "build DNS reply",
                    source,
                })?
            {
                socket
                    .send_to(&response, peer)
                    .await
                    .map_err(|source| DnsServerFailure::Io {
                        operation: "send DNS reply",
                        source,
                    })?;
            }
            Ok(())
        });
        // Preserve responder invocation order without serializing its delay.
        // A closed signal leaves the original panic in the owned reply task.
        tokio::select! {
            biased;
            _ = &mut stopped => break,
            _ = wait_for_call => {}
        }
    }

    replies.abort_all();
    while let Some(outcome) = replies.join_next().await {
        if let Some(error) = reply_failure(outcome, true) {
            failures.push(error);
        }
    }
    failures
}

fn reply_failure(
    outcome: Result<Result<(), DnsServerFailure>, JoinError>,
    stopping: bool,
) -> Option<DnsServerFailure> {
    match outcome {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(error) if stopping && error.is_cancelled() => None,
        Err(error) => Some(DnsServerFailure::Task(error)),
    }
}

/// An SOA authority record's TTL and MINIMUM field.
type SoaFields = (u32, u32);

fn response(query: &DnsQuery, answer: &DnsAnswer) -> io::Result<Option<Vec<u8>>> {
    let recursion = query.flags() & FLAG_RECURSION_DESIRED;
    let (rcode, answers, authority): (u16, &[Vec<u8>], Option<SoaFields>) = match answer {
        DnsAnswer::Records { rdata, .. } => (0, rdata, None),
        DnsAnswer::NoData { soa_minimum } => {
            (0, &[], soa_minimum.map(|minimum| (minimum, minimum)))
        }
        DnsAnswer::NoDataWithSoa { ttl, minimum } => (0, &[], Some((*ttl, *minimum))),
        DnsAnswer::ServerFailure => (RCODE_SERVFAIL, &[], None),
        DnsAnswer::Silence => return Ok(None),
    };
    let ttl = match answer {
        DnsAnswer::Records { ttl, .. } => *ttl,
        _ => 0,
    };
    let answer_count = u16::try_from(answers.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS answer count exceeds 65535"))?;
    let mut message = Vec::new();
    message.extend_from_slice(&query.wire[..2]);
    let flags = FLAG_RESPONSE | recursion | FLAG_RECURSION_AVAILABLE | rcode;
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&answer_count.to_be_bytes());
    message.extend_from_slice(&u16::from(authority.is_some()).to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&query.wire[HEADER_LENGTH..query.question_end]);
    let record_type = query.record_type();
    for rdata in answers {
        push_record(&mut message, record_type, ttl, rdata)?;
    }
    if let Some((soa_ttl, minimum)) = authority {
        let mut soa = Vec::new();
        soa.extend_from_slice(b"\x02ns\x00\x04host\x00");
        for value in [1_u32, 3_600, 600, 86_400, minimum] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        push_record(&mut message, TYPE_SOA, soa_ttl, &soa)?;
    }
    Ok(Some(message))
}

fn push_record(message: &mut Vec<u8>, record_type: u16, ttl: u32, rdata: &[u8]) -> io::Result<()> {
    let length = u16::try_from(rdata.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS record data exceeds 65535 bytes"))?;

    // A compression pointer to the question name at offset 12.
    message.extend_from_slice(&[0xC0, 0x0C]);
    message.extend_from_slice(&record_type.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    message.extend_from_slice(&ttl.to_be_bytes());
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(rdata);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, poll_fn},
        net::UdpSocket as StdUdpSocket,
        pin::pin,
        sync::{
            Weak,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
    };

    use super::*;

    const REPLY_DELAY: Duration = Duration::from_secs(3_600);

    fn query(id: u16, record_type: u16) -> Vec<u8> {
        let mut wire = id.to_be_bytes().to_vec();
        wire.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        wire.extend_from_slice(b"\x04test\x00");
        wire.extend_from_slice(&record_type.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        wire
    }

    async fn wait_for(condition: impl Fn() -> bool) {
        for _ in 0..256 {
            if condition() {
                return;
            }
            tokio::task::yield_now().await;
        }
        assert!(condition(), "the scheduled task did not reach its barrier");
    }

    async fn receive(socket: &StdUdpSocket) -> io::Result<Vec<u8>> {
        let mut buffer = [0; 512];
        for _ in 0..256 {
            match socket.recv_from(&mut buffer) {
                Ok((length, _)) => return Ok(buffer[..length].to_vec()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the scheduled DNS reply did not arrive",
        ))
    }

    fn delayed_server_with_socket() -> io::Result<(DnsServer, Weak<UdpSocket>)> {
        let socket = Arc::new(crate::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?);
        let address = socket.local_addr()?;
        let observed = Arc::downgrade(&socket);
        let queries = Arc::new(Mutex::new(Vec::new()));
        let responder: Arc<Responder> = Arc::new(|_| {
            DnsReply::new(DnsAnswer::Records {
                ttl: 60,
                rdata: vec![vec![127, 0, 0, 1]],
            })
            .delayed(REPLY_DELAY)
        });
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve(socket, Arc::clone(&queries), responder, stopped));
        Ok((
            DnsServer {
                address,
                queries,
                stop: Some(stop),
                task: Some(task),
            },
            observed,
        ))
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn dropping_dns_server_aborts_scheduled_replies_and_releases_socket() -> io::Result<()> {
        let (server, socket) = delayed_server_with_socket()?;
        let address = server.address();
        let peer = crate::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?;
        peer.set_nonblocking(true)?;
        peer.send_to(&query(1, 1), address)?;

        // Both the receiver and its scheduled reply own the socket. A recorded
        // query alone would only establish that the responder was called.
        wait_for(|| socket.strong_count() == 2).await;
        let serving = server
            .task
            .as_ref()
            .ok_or_else(|| io::Error::other("receiver absent"))?
            .abort_handle();
        drop(server);
        wait_for(|| serving.is_finished()).await;
        wait_for(|| socket.strong_count() == 0).await;
        let _rebound = crate::udp::bind(address)?;

        tokio::time::advance(REPLY_DELAY + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        let mut buffer = [0; 512];
        assert_eq!(
            peer.recv_from(&mut buffer).err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock),
            "a reply was sent after dropping the server"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn delayed_reply_does_not_block_another_query() -> Result<(), Box<dyn Error>> {
        let mut server = DnsServer::spawn(|query| {
            let reply = DnsReply::new(DnsAnswer::Records {
                ttl: 60,
                rdata: vec![if query.record_type() == 1 {
                    vec![127, 0, 0, 1]
                } else {
                    vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                }],
            });
            if query.record_type() == 1 {
                reply.delayed(REPLY_DELAY)
            } else {
                reply
            }
        })
        .await?;
        let peer = crate::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?;
        peer.set_nonblocking(true)?;
        peer.send_to(&query(1, 1), server.address())?;
        wait_for(|| server.queries().len() == 1).await;
        let started = tokio::time::Instant::now();
        peer.send_to(&query(2, 28), server.address())?;
        let immediate = receive(&peer).await?;
        assert_eq!(&immediate[..2], &2_u16.to_be_bytes());
        assert_eq!(tokio::time::Instant::now(), started);

        tokio::time::advance(REPLY_DELAY).await;
        let delayed = receive(&peer).await?;
        assert_eq!(&delayed[..2], &1_u16.to_be_bytes());
        assert_eq!(server.queries().len(), 2);
        server.finish().await?;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn cancelling_completion_retains_the_receiver_and_collects_pending_replies()
    -> Result<(), Box<dyn Error>> {
        let (mut server, socket) = delayed_server_with_socket()?;
        let address = server.address();
        let peer = crate::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?;
        peer.send_to(&query(1, 1), address)?;
        wait_for(|| socket.strong_count() == 2).await;

        {
            let mut finishing = pin!(server.finish());
            poll_fn(|context| match finishing.as_mut().poll(context) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(outcome) => panic!("receiver finished before cancellation: {outcome:?}"),
            }).await;
        }
        assert!(server.task.is_some(), "the cancelled wait lost its receiver owner");

        server.finish().await?;
        assert_eq!(socket.strong_count(), 0);
        let rebound = crate::udp::bind(address)?;
        assert_eq!(rebound.local_addr()?, address);
        server.finish().await?;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completion_retains_the_original_responder_panic_payload()
    -> Result<(), Box<dyn Error>> {
        let original = Arc::new("original DNS responder panic");
        let raised = Arc::clone(&original);
        let mut server = DnsServer::spawn(move |_| std::panic::panic_any(Arc::clone(&raised))).await?;
        let peer = crate::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?;
        peer.send_to(&query(1, 1), server.address())?;
        wait_for(|| server.task.as_ref().is_some_and(JoinHandle::is_finished)).await;

        let Err(DnsServerError::Background(mut failures)) = server.finish().await else {
            return Err("responder panic was not reported".into());
        };
        assert_eq!(failures.len(), 1);
        let Some(DnsServerFailure::Task(error)) = failures.pop() else {
            return Err("responder panic lost its original task error".into());
        };
        assert!(error.is_panic());
        let payload = error.into_panic().downcast::<Arc<&str>>()
            .map_err(|_| "responder panic payload changed type")?;
        assert!(Arc::ptr_eq(&payload, &original));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_scripted_replies_report_errors_instead_of_silence()
    -> Result<(), Box<dyn Error>> {
        for rdata in [vec![Vec::new(); 65_536], vec![vec![0; 65_536]]] {
            let mut server = DnsServer::spawn(move |_| DnsReply::new(DnsAnswer::Records {
                ttl: 60,
                rdata: rdata.clone(),
            })).await?;
            let peer = crate::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?;
            peer.send_to(&query(1, 1), server.address())?;
            wait_for(|| server.task.as_ref().is_some_and(JoinHandle::is_finished)).await;

            let Err(DnsServerError::Background(failures)) = server.finish().await else {
                return Err("invalid scripted reply was treated as silence".into());
            };
            let [DnsServerFailure::Io { operation, source }] = failures.as_slice() else {
                return Err("invalid scripted reply lost its I/O error".into());
            };
            assert_eq!(*operation, "build DNS reply");
            assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
        }
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliberate_silence_completes_without_a_reply_or_failure()
    -> Result<(), Box<dyn Error>> {
        let answered = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&answered);
        let mut server = DnsServer::spawn(move |_| {
            observed.store(true, Ordering::SeqCst);
            DnsReply::new(DnsAnswer::Silence)
        }).await?;
        let peer = crate::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?;
        peer.set_nonblocking(true)?;
        peer.send_to(&query(1, 1), server.address())?;
        wait_for(|| answered.load(Ordering::SeqCst)).await;

        server.finish().await?;
        let mut buffer = [0; 512];
        assert_eq!(peer.recv_from(&mut buffer).err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completion_reports_the_original_oversized_datagram_send_error()
    -> Result<(), Box<dyn Error>> {
        let mut server = DnsServer::spawn(|_| DnsReply::new(DnsAnswer::Records {
            ttl: 60,
            rdata: vec![vec![0; 65_535]],
        })).await?;
        let peer = crate::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?;
        peer.send_to(&query(1, 1), server.address())?;
        wait_for(|| server.task.as_ref().is_some_and(JoinHandle::is_finished)).await;

        let Err(DnsServerError::Background(failures)) = server.finish().await else {
            return Err("oversized UDP reply did not report its send failure".into());
        };
        let [failure @ DnsServerFailure::Io { operation, source }] = failures.as_slice() else {
            return Err("UDP send failure lost its original I/O error".into());
        };
        assert_eq!(*operation, "send DNS reply");
        assert!(source.raw_os_error().is_some());
        assert!(std::ptr::eq(failure.source().and_then(|error| error.downcast_ref::<io::Error>())
            .ok_or("UDP failure source lost its concrete I/O error")?, source));
        Ok(())
    }
}
