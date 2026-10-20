use crate::{
    client::{Config, Header, NativeClient},
    error::Failure,
    timeouts::Timeouts,
};
use http_body_util::BodyExt;
use phantom::{Bytes, HttpAttemptBudget, ResponseBody};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::{
        Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::{Notify, oneshot};

pub(super) const MAX_METADATA: usize = 256 * 1024;
pub(super) const MAX_COMMAND: usize = 64 * 1024;
pub(super) const MAX_CHUNK: usize = 64 * 1024;
pub(super) const MAX_UPLOAD: usize = 8 * 1024 * 1024;
const MAX_UPLOADS: usize = 16 * 1024 * 1024;
const MAX_HANDLES: usize = 64;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    NewClient {
        config: Config,
    },
    ReleaseClient {
        client: u64,
    },
    NewBudget {
        maximum: usize,
    },
    ReleaseBudget {
        budget: u64,
    },
    BudgetRemaining {
        budget: u64,
    },
    BudgetAdmit {
        budget: u64,
    },
    CookieSet {
        client: u64,
        url: String,
        value: String,
    },
    CookieGet {
        client: u64,
        url: String,
    },
    CookieClear {
        client: u64,
    },
    Request {
        client: u64,
        method: String,
        url: String,
        headers: Vec<Header>,
        budget: Option<u64>,
        #[serde(default)]
        timeouts: Timeouts,
        has_body: bool,
    },
    Read {
        body: u64,
        maximum: usize,
    },
    CloseBody {
        body: u64,
    },
    Shutdown {
        client: u64,
    },
    Maintain {
        client: u64,
        action: Maintenance,
    },
    ClearState {
        client: u64,
        category: Cache,
    },
    Cancel {
        operation: u64,
    },
    Ack {
        operation: u64,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Maintenance {
    CloseIdleConnections,
    RefreshConnections,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Cache {
    Dns,
    ClientHints,
    AltSvc,
    AltSvcRacingHistory,
    SessionTickets,
}

#[derive(Serialize)]
struct Reply {
    value: Option<Value>,
    error: Option<Failure>,
}

pub(super) fn failure(error: Failure) -> Vec<u8> {
    encode(Err(error))
}

fn encode(result: Result<Value, Failure>) -> Vec<u8> {
    let reply = match result {
        Ok(value) => Reply {
            value: Some(value),
            error: None,
        },
        Err(error) => Reply {
            value: None,
            error: Some(error),
        },
    };
    match serde_json::to_vec(&reply) {
        Ok(bytes) if bytes.len() <= MAX_METADATA => bytes,
        Ok(_) => b"{\"error\":{\"kind\":\"metadata_limit\"}}".to_vec(),
        Err(_) => b"{\"error\":{\"kind\":\"internal\"}}".to_vec(),
    }
}

struct UploadPermit {
    bytes: usize,
    counter: &'static AtomicUsize,
}
impl Drop for UploadPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

struct Stream {
    body: ResponseBody,
    pending: Bytes,
}
struct BodyOwner {
    client: u64,
    stream: Mutex<Option<Stream>>,
    closed: AtomicBool,
    busy: AtomicBool,
    changed: Notify,
    _upload: Option<UploadPermit>,
}
impl BodyOwner {
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
}

struct ReadLease {
    owner: std::sync::Arc<BodyOwner>,
    stream: Option<Stream>,
    restored: bool,
}
impl Drop for ReadLease {
    fn drop(&mut self) {
        if !self.restored {
            self.owner.close();
        }
        self.owner.busy.store(false, Ordering::SeqCst);
    }
}
impl ReadLease {
    async fn read(mut self, maximum: usize) -> Result<Option<Bytes>, Failure> {
        self.stream = self
            .owner
            .stream
            .lock()
            .map_err(|_| Failure::new("internal"))?
            .take();
        let Some(stream) = self.stream.as_mut() else {
            return Ok(None);
        };
        let changed = self.owner.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if self.owner.closed.load(Ordering::SeqCst) {
            return Err(Failure::new("body_closed"));
        }
        let next = async {
            while stream.pending.is_empty() {
                let Some(frame) = stream.body.frame().await else {
                    return Ok::<Option<Bytes>, Failure>(None);
                };
                if let Ok(data) = frame.map_err(Failure::from)?.into_data() {
                    stream.pending = data;
                }
            }
            Ok(Some(
                stream.pending.split_to(maximum.min(stream.pending.len())),
            ))
        };
        let bytes = tokio::select! {
            biased;
            () = &mut changed => return Err(Failure::new("body_closed")),
            result = next => result?,
        };
        if bytes.is_some() {
            let mut slot = self
                .owner
                .stream
                .lock()
                .map_err(|_| Failure::new("internal"))?;
            if !self.owner.closed.load(Ordering::SeqCst) {
                *slot = self.stream.take();
                self.restored = true;
            }
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy)]
enum Target {
    Request(u64),
    Read(u64),
    Shutdown(u64),
    Maintenance(u64),
}
struct Operation {
    target: Target,
    cancel: Option<oneshot::Sender<()>>,
    abandoned: bool,
    finished: bool,
    delivered: bool,
    response: Option<u64>,
}
pub(super) struct Completion {
    pub(super) metadata: Vec<u8>,
    pub(super) data: Bytes,
}
struct Queued {
    operation: u64,
    completion: Completion,
}
struct State {
    failed: bool,
    next: u64,
    clients: HashMap<u64, NativeClient>,
    budgets: HashMap<u64, HttpAttemptBudget>,
    bodies: HashMap<u64, std::sync::Arc<BodyOwner>>,
    operations: HashMap<u64, Operation>,
    ready: VecDeque<Queued>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            failed: false,
            next: 1,
            clients: HashMap::new(),
            budgets: HashMap::new(),
            bodies: HashMap::new(),
            operations: HashMap::new(),
            ready: VecDeque::new(),
        }
    }
}
impl State {
    fn id(&mut self) -> Result<u64, Failure> {
        let id = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| Failure::new("capacity"))?;
        Ok(id)
    }
    fn reserve(&mut self, target: Target) -> Result<(u64, oneshot::Receiver<()>), Failure> {
        match target {
            Target::Shutdown(client) => {
                if self
                    .operations
                    .values()
                    .filter(|op| matches!(op.target, Target::Shutdown(_)))
                    .count()
                    >= MAX_HANDLES
                {
                    return Err(Failure::new("capacity"));
                }
                if self
                    .operations
                    .values()
                    .any(|op| matches!(op.target, Target::Shutdown(id) if id == client))
                {
                    return Err(Failure::new("shutdown_in_progress"));
                }
            }
            _ => {
                if self
                    .operations
                    .values()
                    .filter(|op| !matches!(op.target, Target::Shutdown(_)))
                    .count()
                    >= MAX_HANDLES
                {
                    return Err(Failure::new("capacity"));
                }
            }
        }
        let id = self.id()?;
        let (cancel, receiver) = oneshot::channel();
        self.operations.insert(
            id,
            Operation {
                target,
                cancel: Some(cancel),
                abandoned: false,
                finished: false,
                delivered: false,
                response: None,
            },
        );
        Ok((id, receiver))
    }
    fn close_body(&mut self, body: u64) {
        if let Some(owner) = self.bodies.remove(&body) {
            owner.close();
        }
    }
    fn release_client(&mut self, client: u64) {
        self.clients.remove(&client);
        let bodies: Vec<_> = self
            .bodies
            .iter()
            .filter_map(|(id, owner)| (owner.client == client).then_some(*id))
            .collect();
        for body in &bodies {
            self.close_body(*body);
        }
        let operations: Vec<_> = self
            .operations
            .iter()
            .filter_map(|(id, op)| match op.target {
                Target::Request(owner) | Target::Shutdown(owner) | Target::Maintenance(owner)
                    if owner == client =>
                {
                    Some(*id)
                }
                Target::Read(body) if bodies.contains(&body) => Some(*id),
                _ => None,
            })
            .collect();
        for operation in operations {
            self.cancel(operation);
        }
    }
    fn cancel(&mut self, id: u64) {
        let Some(operation) = self.operations.get_mut(&id) else {
            return;
        };
        operation.abandoned = true;
        if let Some(cancel) = operation.cancel.take() {
            let _ = cancel.send(());
        }
        let body = operation.response.or(match operation.target {
            Target::Read(body) => Some(body),
            _ => None,
        });
        let finished = operation.finished;
        if let Some(body) = body {
            self.close_body(body);
        }
        if finished {
            self.operations.remove(&id);
            self.ready.retain(|entry| entry.operation != id);
        }
    }
}

struct Global {
    state: Mutex<State>,
    ready: Condvar,
    uploads: AtomicUsize,
    runtime: tokio::runtime::Runtime,
}
fn global() -> Result<&'static Global, Failure> {
    static GLOBAL: OnceLock<Result<Global, Failure>> = OnceLock::new();
    GLOBAL
        .get_or_init(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|_| Failure::new("runtime_unavailable"))?;
            Ok(Global {
                state: Mutex::new(State::default()),
                ready: Condvar::new(),
                uploads: AtomicUsize::new(0),
                runtime,
            })
        })
        .as_ref()
        .map_err(Clone::clone)
}

struct Head {
    status: u16,
    protocol: &'static str,
    headers: Vec<Header>,
    body: std::sync::Arc<BodyOwner>,
}
enum Outcome {
    Head(Head),
    Read(Option<Bytes>),
    Complete,
}

impl Global {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => self.recover(poisoned.into_inner()),
        }
    }
    fn recover<'a>(
        &self,
        mut state: std::sync::MutexGuard<'a, State>,
    ) -> std::sync::MutexGuard<'a, State> {
        if !state.failed {
            state.failed = true;
            for (_, body) in state.bodies.drain() {
                body.close();
            }
            state.ready.clear();
            let mut terminal = Vec::new();
            state.operations.retain(|id, operation| {
                if let Some(cancel) = operation.cancel.take() {
                    let _ = cancel.send(());
                }
                operation.response = None;
                operation.finished = true;
                if operation.abandoned {
                    return false;
                }
                if !operation.delivered {
                    terminal.push(*id);
                }
                true
            });
            for id in terminal {
                state.ready.push_back(Queued {
                    operation: id,
                    completion: Completion {
                        metadata: terminal_error(id, "internal"),
                        data: Bytes::new(),
                    },
                });
            }
            self.ready.notify_all();
        }
        state
    }
    fn upload(&'static self, size: usize) -> Result<UploadPermit, Failure> {
        if size > MAX_UPLOAD {
            return Err(Failure::new("upload_limit"));
        }
        let mut used = self.uploads.load(Ordering::SeqCst);
        loop {
            let next = used
                .checked_add(size)
                .filter(|next| *next <= MAX_UPLOADS)
                .ok_or_else(|| Failure::new("capacity"))?;
            match self
                .uploads
                .compare_exchange(used, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(actual) => used = actual,
            }
        }
        Ok(UploadPermit {
            bytes: size,
            counter: &self.uploads,
        })
    }
    fn spawn(
        &'static self,
        id: u64,
        cancel: oneshot::Receiver<()>,
        future: impl Future<Output = Result<Outcome, Failure>> + Send + 'static,
    ) {
        let task = self.runtime.spawn(async move {
            tokio::select! { result = future => result, _ = cancel => Err(Failure::new("cancelled")) }
        });
        self.runtime.spawn(async move {
            let result = task.await.unwrap_or_else(|_| Err(Failure::new("internal")));
            self.finish(id, result);
        });
    }
    fn finish(&self, id: u64, result: Result<Outcome, Failure>) {
        let mut state = self.lock();
        let Some(operation) = state.operations.get(&id) else {
            return;
        };
        if operation.abandoned {
            state.operations.remove(&id);
            return;
        }
        if operation.finished {
            return;
        }
        let mut data = Bytes::new();
        let result = match result {
            Ok(Outcome::Head(head)) => {
                if state.bodies.len() >= MAX_HANDLES {
                    Err(Failure::new("capacity"))
                } else {
                    state.id().map(|body| {
                        state.bodies.insert(body, head.body);
                        if let Some(operation) = state.operations.get_mut(&id) { operation.response = Some(body); }
                        json!({"body":body,"status":head.status,"protocol":head.protocol,"headers":head.headers})
                    })
                }
            }
            Ok(Outcome::Read(bytes)) => {
                if bytes.is_none()
                    && let Some(Operation {
                        target: Target::Read(body),
                        ..
                    }) = state.operations.get(&id)
                {
                    let body = *body;
                    state.close_body(body);
                }
                let eof = bytes.is_none();
                data = bytes.unwrap_or_default();
                Ok(json!({"eof":eof}))
            }
            Ok(Outcome::Complete) => Ok(json!({})),
            Err(error) => {
                if let Some(Operation {
                    target: Target::Read(body),
                    ..
                }) = state.operations.get(&id)
                {
                    let body = *body;
                    state.close_body(body);
                }
                Err(error)
            }
        };
        let reply = match result {
            Ok(value) => Reply {
                value: Some(value),
                error: None,
            },
            Err(error) => Reply {
                value: None,
                error: Some(error),
            },
        };
        let metadata = match serde_json::to_vec(
            &json!({"operation":id,"value":reply.value,"error":reply.error,"data_length":data.len()}),
        ) {
            Ok(bytes) if bytes.len() <= MAX_METADATA => bytes,
            result => {
                let body = state.operations.get(&id).and_then(|operation| {
                    operation.response.or(match operation.target {
                        Target::Read(body) => Some(body),
                        _ => None,
                    })
                });
                if let Some(body) = body {
                    state.close_body(body);
                }
                if let Some(operation) = state.operations.get_mut(&id) {
                    operation.response = None;
                }
                data = Bytes::new();
                terminal_error(
                    id,
                    if result.is_ok() {
                        "metadata_limit"
                    } else {
                        "internal"
                    },
                )
            }
        };
        if let Some(operation) = state.operations.get_mut(&id) {
            operation.finished = true;
            operation.cancel = None;
        }
        state.ready.push_back(Queued {
            operation: id,
            completion: Completion { metadata, data },
        });
        self.ready.notify_one();
    }
}

fn terminal_error(id: u64, kind: &str) -> Vec<u8> {
    // Both fields are internal scalars; this fallback always retains correlation.
    format!("{{\"operation\":{id},\"error\":{{\"kind\":\"{kind}\"}},\"data_length\":0}}")
        .into_bytes()
}

pub(super) fn dispatch(input: &[u8], bytes: &[u8]) -> Vec<u8> {
    encode((|| {
        let command: Command =
            serde_json::from_slice(input).map_err(|_| Failure::new("invalid_command"))?;
        let global = global()?;
        let mut state = global.lock();
        if state.failed
            && !matches!(
                command,
                Command::ReleaseClient { .. }
                    | Command::ReleaseBudget { .. }
                    | Command::CloseBody { .. }
                    | Command::Cancel { .. }
                    | Command::Ack { .. }
            )
        {
            return Err(Failure::new("internal"));
        }
        match command {
            Command::NewClient { config } => {
                if state.clients.len() >= MAX_HANDLES {
                    return Err(Failure::new("capacity"));
                }
                let client = NativeClient::new(config)?;
                let id = state.id()?;
                state.clients.insert(id, client);
                Ok(json!({"id":id}))
            }
            Command::ReleaseClient { client } => {
                state.release_client(client);
                Ok(json!({}))
            }
            Command::NewBudget { maximum } => {
                if state.budgets.len() >= MAX_HANDLES {
                    return Err(Failure::new("capacity"));
                }
                let id = state.id()?;
                state.budgets.insert(id, HttpAttemptBudget::new(maximum));
                Ok(json!({"id":id}))
            }
            Command::ReleaseBudget { budget } => {
                state.budgets.remove(&budget);
                Ok(json!({}))
            }
            Command::BudgetRemaining { budget } => Ok(
                json!({"remaining":state.budgets.get(&budget).ok_or_else(|| Failure::new("invalid_handle"))?.remaining()}),
            ),
            Command::BudgetAdmit { budget } => {
                state
                    .budgets
                    .get(&budget)
                    .ok_or_else(|| Failure::new("invalid_handle"))?
                    .try_admit()
                    .map_err(|_| Failure::new("attempt_budget_exhausted"))?;
                Ok(json!({}))
            }
            Command::CookieSet { client, url, value } => {
                state
                    .clients
                    .get(&client)
                    .ok_or_else(|| Failure::new("invalid_handle"))?
                    .client
                    .cookie_jar()
                    .ok_or_else(|| Failure::new("cookies_disabled"))?
                    .set_cookie(&url, &value)
                    .map_err(|_| Failure::new("invalid_cookie"))?;
                Ok(json!({}))
            }
            Command::CookieGet { client, url } => Ok(
                json!({"cookie":state.clients.get(&client).ok_or_else(|| Failure::new("invalid_handle"))?.client.cookie_jar().ok_or_else(|| Failure::new("cookies_disabled"))?.request_value(&url).map_err(|_| Failure::new("invalid_cookie_url"))?}),
            ),
            Command::CookieClear { client } => {
                state
                    .clients
                    .get(&client)
                    .ok_or_else(|| Failure::new("invalid_handle"))?
                    .client
                    .cookie_jar()
                    .ok_or_else(|| Failure::new("cookies_disabled"))?
                    .clear();
                Ok(json!({}))
            }
            Command::ClearState { client, category } => {
                let client = &state
                    .clients
                    .get(&client)
                    .ok_or_else(|| Failure::new("invalid_handle"))?
                    .client;
                match category {
                    Cache::Dns => client.clear_dns_cache(),
                    Cache::ClientHints => client.clear_client_hints(),
                    Cache::AltSvc => client.clear_alt_svc(),
                    Cache::AltSvcRacingHistory => client.clear_alt_svc_racing_history(),
                    Cache::SessionTickets => {
                        let removed = client
                            .clear_session_tickets()
                            .map_err(|_| Failure::new("session_tickets"))?;
                        return Ok(json!({"removed":removed}));
                    }
                }
                Ok(json!({}))
            }
            Command::Cancel { operation } => {
                state.cancel(operation);
                Ok(json!({}))
            }
            Command::Ack { operation } => {
                let op = state
                    .operations
                    .get(&operation)
                    .ok_or_else(|| Failure::new("invalid_handle"))?;
                if !op.finished {
                    return Err(Failure::new("operation_pending"));
                }
                state.operations.remove(&operation);
                Ok(json!({}))
            }
            Command::CloseBody { body } => {
                state.close_body(body);
                Ok(json!({}))
            }
            Command::Request {
                client,
                method,
                url,
                headers,
                budget,
                timeouts,
                has_body,
            } => {
                let budget = budget
                    .map(|id| {
                        state
                            .budgets
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| Failure::new("invalid_handle"))
                    })
                    .transpose()?;
                let mut request = state
                    .clients
                    .get(&client)
                    .ok_or_else(|| Failure::new("invalid_handle"))?
                    .request(&method, &url, headers, budget, timeouts)?;
                let permit = global.upload(bytes.len())?;
                let (id, cancel) = state.reserve(Target::Request(client))?;
                if has_body {
                    request = request.body(bytes.to_vec());
                }
                drop(state);
                global.spawn(id, cancel, async move {
                    let response = request.send().await.map_err(Failure::from)?;
                    let fields = response
                        .extensions()
                        .get::<phantom::OrderedResponseHeaders>()
                        .ok_or_else(|| Failure::new("ordered_headers_unavailable"))?;
                    let size = fields.iter().try_fold(0usize, |size, field| {
                        size.checked_add(field.name().len())?
                            .checked_add(field.value().len())
                    });
                    if fields.iter().count() > 256 || size.is_none_or(|size| size > 32 * 1024) {
                        return Err(Failure::new("response_headers_limit"));
                    }
                    let headers = fields
                        .iter()
                        .map(|field| Header {
                            name: field.name().to_owned(),
                            value: field.value().to_vec(),
                            sensitive: false,
                        })
                        .collect();
                    let protocol = match response.version() {
                        http::Version::HTTP_11 => "h1",
                        http::Version::HTTP_2 => "h2",
                        http::Version::HTTP_3 => "h3",
                        _ => "unknown",
                    };
                    let status = response.status().as_u16();
                    let owner = std::sync::Arc::new(BodyOwner {
                        client,
                        stream: Mutex::new(Some(Stream {
                            body: response.into_body(),
                            pending: Bytes::new(),
                        })),
                        closed: AtomicBool::new(false),
                        busy: AtomicBool::new(false),
                        changed: Notify::new(),
                        _upload: Some(permit),
                    });
                    Ok(Outcome::Head(Head {
                        status,
                        protocol,
                        headers,
                        body: owner,
                    }))
                });
                Ok(json!({"operation":id}))
            }
            Command::Read { body, maximum } => {
                if maximum == 0 || maximum > MAX_CHUNK {
                    return Err(Failure::new("chunk_size"));
                }
                let owner = state
                    .bodies
                    .get(&body)
                    .cloned()
                    .ok_or_else(|| Failure::new("body_closed"))?;
                let (id, cancel) = state.reserve(Target::Read(body))?;
                if owner
                    .busy
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
                {
                    state.operations.remove(&id);
                    return Err(Failure::new("concurrent_body_read"));
                }
                let lease = ReadLease {
                    owner,
                    stream: None,
                    restored: false,
                };
                drop(state);
                global.spawn(id, cancel, async move {
                    lease.read(maximum).await.map(Outcome::Read)
                });
                Ok(json!({"operation":id}))
            }
            Command::Shutdown { client } => {
                let entry = state
                    .clients
                    .get_mut(&client)
                    .ok_or_else(|| Failure::new("invalid_handle"))?;
                entry.closing = true;
                let native = entry.client.clone();
                let (id, cancel) = state.reserve(Target::Shutdown(client))?;
                drop(state);
                global.spawn(id, cancel, async move {
                    native.shutdown().await;
                    Ok(Outcome::Complete)
                });
                Ok(json!({"operation":id}))
            }
            Command::Maintain { client, action } => {
                let entry = state
                    .clients
                    .get(&client)
                    .ok_or_else(|| Failure::new("invalid_handle"))?;
                if entry.closing {
                    return Err(Failure::new("client_closed"));
                }
                let native = entry.client.clone();
                let (id, cancel) = state.reserve(Target::Maintenance(client))?;
                drop(state);
                global.spawn(id, cancel, async move {
                    match action {
                        Maintenance::CloseIdleConnections => native.close_idle_connections().await,
                        Maintenance::RefreshConnections => native.refresh_connections().await,
                    }
                    Ok(Outcome::Complete)
                });
                Ok(json!({"operation":id}))
            }
        }
    })())
}

pub(super) fn wait() -> Result<Completion, Failure> {
    let global = global()?;
    let mut state = global.lock();
    loop {
        if let Some(queued) = state.ready.pop_front() {
            if let Some(operation) = state.operations.get_mut(&queued.operation) {
                operation.delivered = true;
            }
            return Ok(queued.completion);
        }
        state = match global.ready.wait(state) {
            Ok(state) => state,
            Err(poisoned) => global.recover(poisoned.into_inner()),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_global() -> Result<&'static Global, Failure> {
        Ok(Box::leak(Box::new(Global {
            state: Mutex::new(State::default()),
            ready: Condvar::new(),
            uploads: AtomicUsize::new(0),
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|_| Failure::new("runtime_unavailable"))?,
        })))
    }

    fn empty_owner() -> std::sync::Arc<BodyOwner> {
        std::sync::Arc::new(BodyOwner {
            client: 1,
            stream: Mutex::new(None),
            closed: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            changed: Notify::new(),
            _upload: None,
        })
    }

    #[test]
    fn releasing_client_reclaims_its_bodies_and_reads_without_other_clients() -> Result<(), Failure>
    {
        let mut state = State::default();
        let first = empty_owner();
        let second = std::sync::Arc::new(BodyOwner {
            client: 2,
            stream: Mutex::new(None),
            closed: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            changed: Notify::new(),
            _upload: None,
        });
        state.bodies.insert(20, std::sync::Arc::clone(&first));
        state.bodies.insert(21, std::sync::Arc::clone(&second));
        let (_first_read, mut first_cancel) = state.reserve(Target::Read(20))?;
        let (_second_read, mut second_cancel) = state.reserve(Target::Read(21))?;
        state.release_client(1);
        assert!(first.closed.load(Ordering::SeqCst));
        assert!(!second.closed.load(Ordering::SeqCst));
        assert!(!state.bodies.contains_key(&20));
        assert!(state.bodies.contains_key(&21));
        assert!(first_cancel.try_recv().is_ok());
        assert!(matches!(
            second_cancel.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        Ok(())
    }

    #[test]
    fn maintenance_shares_ordinary_capacity_and_is_cancelled_with_its_client() -> Result<(), Failure>
    {
        let mut state = State::default();
        let (_, mut cancelled) = state.reserve(Target::Maintenance(1))?;
        for _ in 1..MAX_HANDLES {
            state.reserve(Target::Request(2))?;
        }
        assert_eq!(
            state
                .reserve(Target::Maintenance(2))
                .err()
                .map(|error| error.kind),
            Some("capacity")
        );
        state.release_client(1);
        assert!(cancelled.try_recv().is_ok());
        // Cancellation keeps the reservation until native work has settled.
        assert_eq!(state.operations.len(), MAX_HANDLES);
        assert!(state.reserve(Target::Shutdown(2)).is_ok());
        Ok(())
    }

    #[test]
    fn oversized_metadata_returns_typed_correlated_error_and_releases_head() -> Result<(), Failure>
    {
        let reply = encode(Ok(json!({"cookie":"x".repeat(MAX_METADATA)})));
        assert!(reply.len() < MAX_METADATA);
        assert_eq!(
            serde_json::from_slice::<Value>(&reply)
                .ok()
                .and_then(|value| value["error"]["kind"].as_str().map(str::to_owned)),
            Some("metadata_limit".to_owned())
        );
        let global = test_global()?;
        let owner = empty_owner();
        let id = global.lock().reserve(Target::Request(1))?.0;
        global.finish(
            id,
            Ok(Outcome::Head(Head {
                status: 200,
                protocol: "h1",
                headers: vec![Header {
                    name: "x".to_owned(),
                    value: vec![255; MAX_METADATA],
                    sensitive: false,
                }],
                body: owner,
            })),
        );
        let mut state = global.lock();
        assert!(state.bodies.is_empty());
        let completion = state
            .ready
            .pop_front()
            .ok_or_else(|| Failure::new("internal"))?
            .completion;
        let value: Value =
            serde_json::from_slice(&completion.metadata).map_err(|_| Failure::new("internal"))?;
        assert_eq!(value["operation"], id);
        assert_eq!(value["error"]["kind"], "metadata_limit");
        assert!(completion.data.is_empty());
        Ok(())
    }

    #[test]
    fn poisoned_state_terminates_pending_operations_with_their_ids() -> Result<(), Failure> {
        let global = test_global()?;
        let (id, mut receiver) = global.lock().reserve(Target::Request(1))?;
        let _panic = std::panic::catch_unwind(|| {
            let _state = global
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            panic!("test poison");
        });
        let state = global.lock();
        assert!(state.failed);
        assert!(receiver.try_recv().is_ok());
        let queued = state
            .ready
            .front()
            .ok_or_else(|| Failure::new("internal"))?;
        let metadata: Value = serde_json::from_slice(&queued.completion.metadata)
            .map_err(|_| Failure::new("internal"))?;
        assert_eq!(metadata["operation"], id);
        assert_eq!(metadata["error"]["kind"], "internal");
        Ok(())
    }

    #[test]
    fn shutdown_has_reserved_capacity_and_cancelled_work_keeps_its_slot() -> Result<(), Failure> {
        let mut state = State::default();
        let mut receivers = Vec::new();
        for _ in 0..MAX_HANDLES {
            receivers.push(state.reserve(Target::Request(1))?);
        }
        assert_eq!(
            state
                .reserve(Target::Request(1))
                .err()
                .map(|error| error.kind),
            Some("capacity")
        );
        let (shutdown, _receiver) = state.reserve(Target::Shutdown(1))?;
        assert!(state.operations.contains_key(&shutdown));
        assert_eq!(
            state
                .reserve(Target::Shutdown(1))
                .err()
                .map(|error| error.kind),
            Some("shutdown_in_progress")
        );
        let (cancelled, mut receiver) = receivers.remove(0);
        state.cancel(cancelled);
        assert!(receiver.try_recv().is_ok());
        assert_eq!(state.operations.len(), MAX_HANDLES + 1);
        assert!(
            state
                .operations
                .get(&cancelled)
                .is_some_and(|operation| operation.abandoned)
        );
        let mut shutdowns = State::default();
        for client in 0..MAX_HANDLES as u64 {
            let (id, _receiver) = shutdowns.reserve(Target::Shutdown(client))?;
            shutdowns.cancel(id);
        }
        assert_eq!(
            shutdowns
                .reserve(Target::Shutdown(MAX_HANDLES as u64))
                .err()
                .map(|error| error.kind),
            Some("capacity")
        );
        Ok(())
    }

    #[test]
    fn abandoned_delivered_heads_release_body_and_upload_custody() -> Result<(), Failure> {
        let global = test_global()?;
        let first = global.upload(MAX_UPLOAD)?;
        let second = global.upload(MAX_UPLOAD)?;
        assert_eq!(
            global.upload(1).err().map(|error| error.kind),
            Some("capacity")
        );
        assert_eq!(
            global.upload(MAX_UPLOAD + 1).err().map(|error| error.kind),
            Some("upload_limit")
        );
        drop(second);
        let owner = std::sync::Arc::new(BodyOwner {
            client: 1,
            stream: Mutex::new(None),
            closed: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            changed: Notify::new(),
            _upload: Some(first),
        });
        let id = {
            let mut state = global.state.lock().map_err(|_| Failure::new("internal"))?;
            state.reserve(Target::Request(1))?.0
        };
        global.finish(
            id,
            Ok(Outcome::Head(Head {
                status: 200,
                protocol: "h1",
                headers: Vec::new(),
                body: std::sync::Arc::clone(&owner),
            })),
        );
        // Taking a completion does not transfer its body: only host Ack does.
        let completion = global
            .lock()
            .ready
            .pop_front()
            .ok_or_else(|| Failure::new("internal"))?
            .completion;
        assert!(completion.metadata.len() <= MAX_METADATA);
        {
            let mut state = global.state.lock().map_err(|_| Failure::new("internal"))?;
            assert_eq!(state.bodies.len(), 1);
            state.cancel(id);
            assert!(state.bodies.is_empty());
            assert!(state.operations.is_empty());
        }
        assert!(owner.closed.load(Ordering::SeqCst));
        assert_eq!(global.uploads.load(Ordering::SeqCst), MAX_UPLOAD);
        drop(owner);
        assert_eq!(global.uploads.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
