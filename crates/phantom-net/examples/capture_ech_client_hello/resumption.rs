//! Ticket-linked ECH and early-data observations on the existing TCP origin.

use std::{collections::BTreeMap, str::FromStr};

use btls::{
    ex_data::Index,
    ssl::{SslAcceptorBuilder, SslMessage, SslMessageContentType, SslMessageDirection},
};

use super::*;

const MAX_MESSAGES: usize = 8;
const MAX_EARLY_BYTES: usize = 64 * 1024;
const INNER_CLIENT_HELLO: i32 = 0x101; // Pinned BoringSSL ssl3.h.
const SEED: &str = "/seed";
const RESUME: &str = "/resume?probe=ech-early-data";
const SEED_PAGE: &[u8] =
    br#"<!doctype html><meta charset=utf-8><link rel=icon href="data:,"><script>
fetch('/resume?probe=ech-early-data', {cache:'no-store'}).then(r => r.arrayBuffer());
</script>"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    EarlyAccept,
    EarlyReject,
    EchRetry,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::EarlyAccept => "early-accept",
            Self::EarlyReject => "early-reject",
            Self::EchRetry => "ech-retry",
        }
    }
}

impl FromStr for Mode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "early-accept" => Ok(Self::EarlyAccept),
            "early-reject" => Ok(Self::EarlyReject),
            "ech-retry" => Ok(Self::EchRetry),
            _ => Err("unknown ECH resumption sequence"),
        }
    }
}

#[derive(Default)]
struct Observation {
    outer_records_sha256: String,
    early_enabled: bool,
    after_probe_fence: bool,
    offers: Vec<Offer>,
    tickets: Vec<Ticket>,
    handshake_complete: bool,
    resumed: bool,
    early_accepted: bool,
    early_bytes: usize,
    early_sha256: Option<String>,
    requests: Vec<Request>,
    error: Option<&'static str>,
}

#[derive(Debug, PartialEq, Eq)]
struct Offer {
    early_data: bool,
    tickets: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Ticket {
    sha256: String,
    max_early_data: Option<u32>,
}

struct Request {
    path: &'static str,
    head_sha256: String,
    early_bytes: usize,
    served: bool,
}

#[derive(Default)]
struct State {
    connections: BTreeMap<usize, Observation>,
    seed: Option<usize>,
    seed_flushed: bool,
    rotated: bool,
    probe_released: bool,
    retirement: Option<Retirement>,
    setup_retired: Vec<usize>,
}

pub(super) struct Retirement {
    seed: usize,
    released: oneshot::Sender<()>,
}

pub(super) struct Run {
    mode: Mode,
    index: Index<Ssl, usize>,
    state: Mutex<State>,
    retire: Notify,
}

impl Run {
    pub(super) fn new(mode: Mode) -> CaptureResult<Arc<Self>> {
        Ok(Arc::new(Self {
            mode,
            index: Ssl::new_ex_index()?,
            state: Mutex::default(),
            retire: Notify::new(),
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn observe(self: &Arc<Self>, builder: &mut SslAcceptorBuilder) {
        let run = Arc::clone(self);
        builder.set_msg_callback(move |ssl, message| {
            if let Some(slot) = ssl.ex_data(run.index) {
                run.message(*slot, message);
            }
        });
    }

    pub(super) fn configure(&self, ssl: &mut Ssl, slot: usize, outer_records: &[u8]) {
        let mut state = self.lock();
        let after_probe_fence = state.probe_released;
        let early_enabled = self.mode != Mode::EarlyReject || state.seed.is_none();
        state.connections.insert(
            slot,
            Observation {
                early_enabled,
                after_probe_fence,
                outer_records_sha256: digest(outer_records),
                ..Observation::default()
            },
        );
        ssl.set_ex_data(self.index, slot);
        ssl.set_early_data_enabled(early_enabled);
    }

    async fn prepare_probe(&self, _seed: usize) -> CaptureResult<()> {
        Ok(())
    }

    pub(super) async fn retirement_requested(run: Option<&Self>) -> Retirement {
        let Some(run) = run else {
            return std::future::pending().await;
        };
        loop {
            let notified = run.retire.notified();
            if let Some(request) = run.lock().retirement.take() {
                return request;
            }
            notified.await;
        }
    }

    /// Join every accepted pre-probe TCP owner, including sockets which have
    /// not sent a ClientHello. The seed is waiting with its page body withheld.
    pub(super) async fn retire_workers(
        &self,
        request: Retirement,
        tasks: &mut JoinSet<CaptureResult<()>>,
        workers: &mut BTreeMap<tokio::task::Id, (usize, tokio::task::AbortHandle)>,
        acceptor: &SslAcceptor,
    ) -> CaptureResult<()> {
        let seed = workers
            .iter()
            .find_map(|(id, (slot, _))| (*slot == request.seed).then_some(*id))
            .ok_or("seed worker missing before probe retirement")?;
        for (id, (_, handle)) in workers.iter() {
            if *id != seed {
                handle.abort();
            }
        }
        timeout(HANDSHAKE_TIMEOUT, async {
            while workers.len() > 1 {
                let joined = tasks
                    .join_next_with_id()
                    .await
                    .ok_or("origin workers disappeared during probe retirement")?;
                let (id, result) = match joined {
                    Ok((id, result)) => (id, result),
                    Err(error) if error.is_cancelled() => (error.id(), Ok(())),
                    Err(error) => return Err(error.into()),
                };
                let (slot, _) = workers
                    .remove(&id)
                    .ok_or("unknown origin worker joined during probe retirement")?;
                result?;
                if id == seed {
                    return Err("seed worker stopped during probe retirement".into());
                }
                self.lock().setup_retired.push(slot);
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        })
        .await??;
        if self.mode == Mode::EchRetry {
            let mut keys = SslEchKeys::builder()?;
            keys.add_key(
                true,
                &ech_config(2, &TEST_ECH_KEYS[1], PUBLIC_NAME),
                HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[1].private_key)?,
            )?;
            acceptor.context().set_ech_keys(&keys.build())?;
        }
        {
            let mut state = self.lock();
            state.rotated = self.mode == Mode::EchRetry;
            state.probe_released = true;
        }
        request
            .released
            .send(())
            .map_err(|_| "seed stopped before probe release".into())
    }

    fn message(&self, slot: usize, message: SslMessage<'_>) {
        let parsed = if message.direction == SslMessageDirection::Read
            && message.content_type.as_raw() == INNER_CLIENT_HELLO
        {
            Some(parse_offer(message.data).map(Message::Offer))
        } else if message.direction == SslMessageDirection::Write
            && message.content_type == SslMessageContentType::HANDSHAKE
            && message.data.first() == Some(&4)
        {
            Some(parse_ticket(message.data).map(Message::Ticket))
        } else {
            None
        };
        let Some(parsed) = parsed else { return };
        let mut state = self.lock();
        let Some(observed) = state.connections.get_mut(&slot) else {
            return;
        };
        match parsed {
            Ok(Message::Offer(offer)) if observed.offers.len() < MAX_MESSAGES => {
                observed.offers.push(offer);
            }
            Ok(Message::Ticket(ticket)) if observed.tickets.len() < MAX_MESSAGES => {
                observed.tickets.push(ticket);
            }
            Ok(_) => observed.error = Some("too many TLS observation messages"),
            Err(error) => observed.error = Some(error),
        }
    }

    pub(super) async fn serve(
        &self,
        mut tls: SslStream<Replayed>,
        acceptor: SslAcceptor,
        captured: Arc<Captured>,
        slot: usize,
        mut connection: Connection,
    ) -> CaptureResult<()> {
        // Preserve partial records if this is an idle speculative connection
        // stopped by the existing grace owner.
        connection.handshake = Err("not completed".to_owned());
        captured.store_tcp(slot, connection.clone());
        let exchange = async {
            Pin::new(&mut tls).accept().await?;
            connection.ech_accepted = tls.ssl().ech_accepted();
            connection.inner_server_name =
                tls.ssl().servername(NameType::HOST_NAME).map(str::to_owned);
            self.native_state(slot, tls.ssl());
            if tls.ssl().is_init_finished() {
                connection.handshake = Ok(());
            }
            captured.store_tcp(slot, connection.clone());
            let mut early = EarlyPlaintext::new();
            let head = read_head(&mut tls, self, slot, &mut early).await?;
            let Some(head) = head else {
                return Ok::<(), Box<dyn Error + Send + Sync>>(());
            };
            let path = request_path(&head)?;
            finish_server_handshake(&mut tls, self, slot, &mut early).await?;
            connection.handshake = Ok(());
            connection.ech_accepted = tls.ssl().ech_accepted();
            connection.inner_server_name =
                tls.ssl().servername(NameType::HOST_NAME).map(str::to_owned);
            let seed = {
                let mut state = self.lock();
                let is_seed = path == SEED && state.seed.is_none();
                if is_seed {
                    if !connection.ech_accepted {
                        return Err("seed request did not authenticate ECH".into());
                    }
                    state.seed = Some(slot);
                }
                let observed = state
                    .connections
                    .get_mut(&slot)
                    .ok_or("missing TLS observation")?;
                observed.handshake_complete = true;
                observed.resumed = tls.ssl().session_reused();
                observed.early_accepted = tls.ssl().early_data_accepted();
                observed.requests.push(Request {
                    path,
                    head_sha256: digest(&head),
                    early_bytes: early.bytes,
                    served: false,
                });
                is_seed
            };
            let body = if seed { SEED_PAGE } else { b"ok" };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            tls.write_all(response.as_bytes()).await?;
            if seed {
                self.prepare_probe(slot).await?;
            }
            tls.write_all(body).await?;
            tls.flush().await?;
            if seed {
                // This owner runs on the current-thread executor. Rotate
                // synchronously after flushing the seed response, before the
                // next await can admit another native handshake operation.
                if self.mode == Mode::EchRetry {
                    let mut keys = SslEchKeys::builder()?;
                    keys.add_key(
                        true,
                        &ech_config(2, &TEST_ECH_KEYS[1], PUBLIC_NAME),
                        HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[1].private_key)?,
                    )?;
                    acceptor.context().set_ech_keys(&keys.build())?;
                }
                let mut state = self.lock();
                state.seed_flushed = true;
                state.rotated = self.mode == Mode::EchRetry;
            }
            tls.shutdown().await?;
            {
                let mut state = self.lock();
                let request = state
                    .connections
                    .get_mut(&slot)
                    .and_then(|observed| observed.requests.last_mut())
                    .ok_or("missing served request")?;
                request.served = true;
            }
            connection.request_served = true;
            if path == RESUME {
                captured.mark_served();
            }
            Ok(())
        };
        let result = timeout(HANDSHAKE_TIMEOUT, exchange).await;
        self.native_state(slot, tls.ssl());
        if tls.ssl().is_init_finished() {
            connection.handshake = Ok(());
        }
        match result {
            Ok(Ok(())) => {
                captured.store_tcp(slot, connection);
                Ok(())
            }
            Ok(Err(error)) => {
                connection.handshake = Err(error.to_string());
                captured.store_tcp(slot, connection);
                Err(error)
            }
            Err(_) => {
                connection.handshake = Err("resumption exchange timed out".to_owned());
                captured.store_tcp(slot, connection);
                Err("resumption exchange timed out".into())
            }
        }
    }

    fn native_state(&self, slot: usize, ssl: &btls::ssl::SslRef) {
        if let Some(observed) = self.lock().connections.get_mut(&slot) {
            observed.handshake_complete = ssl.is_init_finished();
            observed.resumed = ssl.session_reused();
            observed.early_accepted = ssl.early_data_accepted();
        }
    }

    pub(super) fn write(&self, output: &mut impl io::Write) -> io::Result<()> {
        let state = self.lock();
        if let Some(error) = state.connections.values().find_map(|value| value.error) {
            return Err(io::Error::other(error));
        }
        writeln!(output, "resumption_sequence={}", self.mode.name())?;
        writeln!(
            output,
            "resumption_seed_slot={}",
            state
                .seed
                .map_or_else(|| "none".to_owned(), |slot| slot.to_string())
        )?;
        writeln!(output, "resumption_seed_flushed={}", state.seed_flushed)?;
        writeln!(output, "resumption_ech_rotated={}", state.rotated)?;
        writeln!(output, "resumption_probe_released={}", state.probe_released)?;
        writeln!(
            output,
            "resumption_setup_retired_slots={}",
            state
                .setup_retired
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )?;
        let seed_tickets = state
            .seed
            .and_then(|slot| state.connections.get(&slot))
            .map(|value| &value.tickets);
        let served = state
            .connections
            .values()
            .flat_map(|value| &value.requests)
            .filter(|request| request.path == RESUME && request.served)
            .count();
        writeln!(output, "resumption_served_probe_gets={served}")?;
        for (slot, observed) in &state.connections {
            let prefix = format!("resumption_slot_{slot}");
            writeln!(
                output,
                "{prefix}_outer_records_sha256={}",
                observed.outer_records_sha256
            )?;
            writeln!(
                output,
                "{prefix}_early_data_enabled={}",
                observed.early_enabled
            )?;
            writeln!(
                output,
                "{prefix}_after_probe_fence={}",
                observed.after_probe_fence
            )?;
            writeln!(
                output,
                "{prefix}_handshake_complete={}",
                observed.handshake_complete
            )?;
            writeln!(output, "{prefix}_session_reused={}", observed.resumed)?;
            writeln!(
                output,
                "{prefix}_early_data_accepted={}",
                observed.early_accepted
            )?;
            writeln!(
                output,
                "{prefix}_early_plaintext_bytes={}",
                observed.early_bytes
            )?;
            writeln!(
                output,
                "{prefix}_early_plaintext_sha256={}",
                observed.early_sha256.as_deref().unwrap_or("none")
            )?;
            for (index, offer) in observed.offers.iter().enumerate() {
                writeln!(
                    output,
                    "{prefix}_inner_{index}_early_data_offered={}",
                    offer.early_data
                )?;
                writeln!(
                    output,
                    "{prefix}_inner_{index}_psk_sha256={}",
                    offer.tickets.join(",")
                )?;
                let matched = offer
                    .tickets
                    .iter()
                    .filter(|hash| {
                        seed_tickets.is_some_and(|tickets| {
                            tickets.iter().any(|ticket| &ticket.sha256 == *hash)
                        })
                    })
                    .count();
                writeln!(
                    output,
                    "{prefix}_inner_{index}_seed_ticket_matches={matched}"
                )?;
            }
            for (index, ticket) in observed.tickets.iter().enumerate() {
                writeln!(output, "{prefix}_ticket_{index}_sha256={}", ticket.sha256)?;
                writeln!(
                    output,
                    "{prefix}_ticket_{index}_max_early_data={}",
                    ticket
                        .max_early_data
                        .map_or_else(|| "none".to_owned(), |size| size.to_string())
                )?;
            }
            for (index, request) in observed.requests.iter().enumerate() {
                writeln!(
                    output,
                    "{prefix}_request_{index}=GET {},head_sha256={},early_bytes={},served={}",
                    request.path, request.head_sha256, request.early_bytes, request.served
                )?;
            }
        }
        Ok(())
    }
}

enum Message {
    Offer(Offer),
    Ticket(Ticket),
}

fn digest(bytes: &[u8]) -> String {
    hex(&btls::sha::sha256(bytes))
}

struct EarlyPlaintext {
    bytes: usize,
    hash: btls::sha::Sha256,
}

impl EarlyPlaintext {
    fn new() -> Self {
        Self {
            bytes: 0,
            hash: btls::sha::Sha256::new(),
        }
    }

    fn observe(&mut self, run: &Run, slot: usize, byte: u8) -> io::Result<()> {
        if self.bytes == MAX_EARLY_BYTES {
            return Err(io::Error::other("early data exceeds capture limit"));
        }
        self.bytes += 1;
        self.hash.update(&[byte]);
        let mut state = run.lock();
        let observed = state
            .connections
            .get_mut(&slot)
            .ok_or_else(|| io::Error::other("missing TLS observation"))?;
        // Preserve partial plaintext facts when the existing owner cancels.
        observed.early_bytes = self.bytes;
        observed.early_sha256 = Some(hex(&self.hash.clone().finish()));
        Ok(())
    }
}

async fn read_head(
    tls: &mut SslStream<Replayed>,
    run: &Run,
    slot: usize,
    early: &mut EarlyPlaintext,
) -> io::Result<Option<Vec<u8>>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == MAX_REQUEST_HEAD {
            return Err(io::Error::other("request head exceeds capture limit"));
        }
        let mut byte = [0];
        if tls.read(&mut byte).await? == 0 {
            return Ok(None);
        }
        // The native record layer has returned plaintext while Finished is
        // still pending; ciphertext lengths/ClientHello intent are not used.
        if !tls.ssl().is_init_finished() {
            early.observe(run, slot, byte[0])?;
        }
        head.push(byte[0]);
    }
    Ok(Some(head))
}

async fn finish_server_handshake(
    tls: &mut SslStream<Replayed>,
    run: &Run,
    slot: usize,
    early: &mut EarlyPlaintext,
) -> io::Result<()> {
    std::future::poll_fn(|cx| {
        if tls.ssl().is_init_finished() {
            return Poll::Ready(Ok(()));
        }
        let mut byte = [0];
        let mut buffer = ReadBuf::new(&mut byte);
        let result = Pin::new(&mut *tls).poll_read(cx, &mut buffer);
        match result {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) if !buffer.filled().is_empty() => {
                if !tls.ssl().is_init_finished() {
                    early.observe(run, slot, buffer.filled()[0])?;
                }
                Poll::Ready(Err(io::Error::other(
                    "unexpected application data after request head",
                )))
            }
            Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed before the resumption response",
            ))),
            // Server SSL_do_handshake returns early while can_early_read is
            // set. SSL_read consumes EndOfEarlyData/Finished, then may wait
            // for application data. Finished is sufficient for this GET.
            Poll::Pending if tls.ssl().is_init_finished() => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

fn request_path(head: &[u8]) -> CaptureResult<&'static str> {
    let line = head
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or("missing request line")?;
    match line {
        b"GET /seed HTTP/1.1\r" => Ok(SEED),
        b"GET /resume?probe=ech-early-data HTTP/1.1\r" => Ok(RESUME),
        _ => Err("unexpected resumption request".into()),
    }
}

fn parse_offer(message: &[u8]) -> Result<Offer, &'static str> {
    let mut body = Cursor::message(message, 1)?;
    ClientHelloSummary::from_handshake_bytes(message).map_err(|_| "invalid inner ClientHello")?;
    body.take(34)?;
    body.vector(1)?;
    body.vector(2)?;
    body.vector(1)?;
    let mut extensions = Cursor(body.vector(2)?);
    body.finish()?;
    let mut early_data = false;
    let mut tickets = Vec::new();
    while !extensions.0.is_empty() {
        let kind = extensions.number(2)?;
        let value = extensions.vector(2)?;
        if kind == 42 {
            if !value.is_empty() {
                return Err("invalid early-data extension");
            }
            early_data = true;
        } else if kind == 41 {
            let mut psk = Cursor(value);
            let mut identities = Cursor(psk.vector(2)?);
            while !identities.0.is_empty() {
                if tickets.len() == MAX_MESSAGES {
                    return Err("too many PSK identities");
                }
                let identity = identities.vector(2)?;
                if identity.is_empty() {
                    return Err("empty PSK identity");
                }
                tickets.push(digest(identity));
                identities.take(4)?;
            }
            let mut binders = Cursor(psk.vector(2)?);
            let mut count = 0;
            while !binders.0.is_empty() {
                if binders.vector(1)?.len() < 32 {
                    return Err("short PSK binder");
                }
                count += 1;
            }
            psk.finish()?;
            if tickets.is_empty() || count != tickets.len() {
                return Err("PSK identity/binder count mismatch");
            }
        }
    }
    Ok(Offer {
        early_data,
        tickets,
    })
}

fn parse_ticket(message: &[u8]) -> Result<Ticket, &'static str> {
    let mut body = Cursor::message(message, 4)?;
    body.take(8)?;
    body.vector(1)?;
    let ticket = body.vector(2)?;
    if ticket.is_empty() {
        return Err("empty session ticket");
    }
    let sha256 = digest(ticket);
    let mut extensions = Cursor(body.vector(2)?);
    body.finish()?;
    let mut max_early_data = None;
    while !extensions.0.is_empty() {
        let kind = extensions.number(2)?;
        let mut value = Cursor(extensions.vector(2)?);
        if kind == 42 {
            if max_early_data.is_some() {
                return Err("duplicate early-data ticket extension");
            }
            max_early_data = Some(value.number(4)?);
            value.finish()?;
        }
    }
    Ok(Ticket {
        sha256,
        max_early_data,
    })
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn message(bytes: &'a [u8], kind: u8) -> Result<Self, &'static str> {
        if bytes.len() > 128 * 1024 {
            return Err("TLS message exceeds capture limit");
        }
        let mut cursor = Self(bytes);
        if cursor.number(1)? != u32::from(kind) {
            return Err("unexpected TLS message");
        }
        let length = cursor.number(3)? as usize;
        let body = cursor.take(length)?;
        cursor.finish()?;
        Ok(Self(body))
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], &'static str> {
        let value = self.0.get(..count).ok_or("truncated TLS observation")?;
        self.0 = &self.0[count..];
        Ok(value)
    }

    fn number(&mut self, width: usize) -> Result<u32, &'static str> {
        Ok(self
            .take(width)?
            .iter()
            .fold(0, |value, byte| (value << 8) | u32::from(*byte)))
    }

    fn vector(&mut self, width: usize) -> Result<&'a [u8], &'static str> {
        let size = self.number(width)? as usize;
        self.take(size)
    }

    fn finish(self) -> Result<(), &'static str> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("trailing TLS observation bytes")
        }
    }
}

#[cfg(test)]
#[path = "resumption/tests.rs"]
mod tests;
