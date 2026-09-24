//! A scripted loopback DNS responder that records every query it receives.
//!
//! It answers over UDP only, which suffices for responses that fit in 512
//! bytes, and it echoes each question so resolvers accept the response.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tokio::{net::UdpSocket, task::JoinHandle};

const HEADER_LENGTH: usize = 12;
const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const RCODE_SERVFAIL: u16 = 2;
const TYPE_SOA: u16 = 6;
const CLASS_IN: u16 = 1;

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

/// A UDP DNS responder on an ephemeral IPv4 loopback port.
pub struct DnsServer {
    address: SocketAddr,
    queries: Arc<Mutex<Vec<DnsQuery>>>,
    task: JoinHandle<()>,
}

impl DnsServer {
    /// Binds `127.0.0.1:0` and answers each query with `responder`.
    ///
    /// # Errors
    ///
    /// Returns the bind error.
    pub async fn spawn(
        responder: impl Fn(&DnsQuery) -> DnsReply + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
        let address = socket.local_addr()?;
        let queries = Arc::new(Mutex::new(Vec::new()));
        let responder: Arc<Responder> = Arc::new(responder);
        let task = tokio::spawn(serve(socket, Arc::clone(&queries), responder));
        Ok(Self {
            address,
            queries,
            task,
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
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    socket: Arc<UdpSocket>,
    queries: Arc<Mutex<Vec<DnsQuery>>>,
    responder: Arc<Responder>,
) {
    let mut buffer = vec![0; 65_535];
    loop {
        let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
            // Windows reports an ICMP port-unreachable for an earlier reply
            // as a receive error; keep serving.
            continue;
        };
        let Some(query) = DnsQuery::parse(&buffer[..length]) else {
            continue;
        };
        queries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(query.clone());
        let reply = responder(&query);
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            if !reply.delay.is_zero() {
                tokio::time::sleep(reply.delay).await;
            }
            if let Some(response) = response(&query, &reply.answer) {
                let _ = socket.send_to(&response, peer).await;
            }
        });
    }
}

fn response(query: &DnsQuery, answer: &DnsAnswer) -> Option<Vec<u8>> {
    let recursion = query.flags() & FLAG_RECURSION_DESIRED;
    let (rcode, answers, authority): (u16, &[Vec<u8>], Option<u32>) = match answer {
        DnsAnswer::Records { rdata, .. } => (0, rdata, None),
        DnsAnswer::NoData { soa_minimum } => (0, &[], *soa_minimum),
        DnsAnswer::ServerFailure => (RCODE_SERVFAIL, &[], None),
        DnsAnswer::Silence => return None,
    };
    let ttl = match answer {
        DnsAnswer::Records { ttl, .. } => *ttl,
        _ => 0,
    };
    let mut message = Vec::new();
    message.extend_from_slice(&query.wire[..2]);
    let flags = FLAG_RESPONSE | recursion | FLAG_RECURSION_AVAILABLE | rcode;
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&u16::try_from(answers.len()).ok()?.to_be_bytes());
    message.extend_from_slice(&u16::from(authority.is_some()).to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&query.wire[HEADER_LENGTH..query.question_end]);
    let record_type = query.record_type();
    for rdata in answers {
        push_record(&mut message, record_type, ttl, rdata)?;
    }
    if let Some(minimum) = authority {
        let mut soa = Vec::new();
        soa.extend_from_slice(b"\x02ns\x00\x04host\x00");
        for value in [1_u32, 3_600, 600, 86_400, minimum] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        push_record(&mut message, TYPE_SOA, minimum, &soa)?;
    }
    Some(message)
}

fn push_record(message: &mut Vec<u8>, record_type: u16, ttl: u32, rdata: &[u8]) -> Option<()> {
    // A compression pointer to the question name at offset 12.
    message.extend_from_slice(&[0xC0, 0x0C]);
    message.extend_from_slice(&record_type.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    message.extend_from_slice(&ttl.to_be_bytes());
    message.extend_from_slice(&u16::try_from(rdata.len()).ok()?.to_be_bytes());
    message.extend_from_slice(rdata);
    Some(())
}
