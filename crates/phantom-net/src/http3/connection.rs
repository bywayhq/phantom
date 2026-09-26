use std::{
    future::poll_fn,
    pin::pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU8, Ordering},
    },
};

use bytes::Bytes;
use h3::{ConnectionState, client::PeerSettings};
use http::{Request, Response};
use tokio::{
    runtime::Handle,
    sync::{Mutex, MutexGuard},
};
use tracing::{Instrument, debug, debug_span, field};

use crate::accept_ch::AcceptCh;

use super::{
    DatagramRouter, DriverSignal, DriverTask, Http3Body, Http3Error, Http3ErrorKind,
    Http3ExtendedConnectOutcome, Http3ExtendedConnectStream, Http3ExtendedProtocol, PendingRequest,
    RequestRecvStream, RequestSendStream, ResponseHeadError, body,
    datagram::DatagramFlow,
    driver_unavailable,
    early_data::{EarlyData, EarlyDataOutcome},
    receive_response,
    request::PreparedRequest,
    upload::{RequestSend, UploadError},
};
use crate::request::RequestBody;

pub(super) type RequestSender = h3::client::SendRequest<super::early_streams::Opener<Bytes>, Bytes>;

/// Cloneable handle to one established HTTP/3 connection.
///
/// Clones open independent request streams over the same QUIC connection. The
/// final connection or response-body lease starts bounded driver shutdown.
/// Send requests through the [`super::Http3Connector`] that opened the handle.
#[derive(Clone)]
pub struct Http3Connection {
    inner: Arc<ConnectionInner>,
}

/// The HTTP/3 session a connection sends its requests on.
///
/// A connection whose early data was rejected replaces its session once, with
/// one started on the same QUIC connection after the handshake.
pub(super) struct Session {
    // Serializes `send_request` so stream IDs, QPACK encoder instructions, and
    // datagram monitor registration follow call order. Health checks must not
    // take this lock: `send_request` can wait for peer SETTINGS, QPACK
    // admission, or MAX_STREAMS credit while holding it.
    sender: Mutex<Option<RequestSender>>,
    state: std::sync::Mutex<PeerSettings>,
}

impl Session {
    pub(super) fn new(sender: RequestSender) -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(sender.peer_settings()),
            sender: Mutex::new(Some(sender)),
        })
    }

    /// Sends later requests on `sender`, dropping the session it replaces.
    ///
    /// The new session numbers its request streams again from the first
    /// unused one: 0, or the stream after one the early session reset
    /// unused. The datagram router therefore forgets the old session's
    /// stream order under the same lock.
    pub(super) async fn replace(&self, sender: RequestSender, datagrams: Option<&DatagramRouter>) {
        let state = sender.peer_settings();
        let mut current = self.sender.lock().await;
        if let Some(datagrams) = datagrams {
            datagrams.restart();
        }
        *lock_state(&self.state) = state;
        *current = Some(sender);
    }

    fn is_healthy(&self) -> bool {
        let state = lock_state(&self.state);
        !state.is_closing() && state.get_conn_error().is_none()
    }
}

fn lock_state(state: &std::sync::Mutex<PeerSettings>) -> std::sync::MutexGuard<'_, PeerSettings> {
    match state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct ConnectionInner {
    session: Arc<Session>,
    driver: DriverTask,
    datagrams: Option<DatagramRouter>,
    quinn: quinn::Connection,
    signal: AtomicU8,
    connector_identity: Option<Arc<()>>,
    runtime: Handle,
    /// Set before the connection is returned, or, on a connection that sent
    /// early data, when its accepted handshake completes.
    accept_ch: Arc<OnceLock<AcceptCh>>,
    early_data: Option<EarlyData>,
    remembered_settings: bool,
}

impl Http3Connection {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        session: Arc<Session>,
        driver: DriverTask,
        datagrams: Option<DatagramRouter>,
        quinn: quinn::Connection,
        connector_identity: Option<Arc<()>>,
        accept_ch: Arc<OnceLock<AcceptCh>>,
        early_data: Option<EarlyData>,
        remembered_settings: bool,
    ) -> Self {
        Self {
            inner: Arc::new(ConnectionInner {
                session,
                driver,
                datagrams,
                quinn,
                signal: AtomicU8::new(DriverSignal::Complete.rank()),
                connector_identity,
                runtime: Handle::current(),
                accept_ch,
                early_data,
                remembered_settings,
            }),
        }
    }

    /// Returns this connection's ALPS-delivered `Accept-CH` value for `origin`.
    ///
    /// The lookup is an exact byte match against the origin serialized in the
    /// peer's HTTP/3 `ACCEPT_CH` frame. The metadata is immutable and remains
    /// scoped to this connection. A connection that sent early data learns it
    /// when the server answers the early data and the handshake metadata
    /// passes its checks; before then this returns `None`.
    #[must_use]
    pub fn accept_ch_for_origin(&self, origin: &str) -> Option<&[u8]> {
        self.inner.accept_ch.get()?.for_origin(origin)
    }

    /// Returns whether this connection sent early (0-RTT) data.
    ///
    /// Only a connector from [`super::Http3Connector::with_early_data`] sends
    /// early data, and only when it resumes with a ticket that permits it.
    /// Such a connection is returned before its handshake completes. Every
    /// replay-safe request sent before the server's answer to the early data
    /// settles goes out as early data; every other request waits for the
    /// handshake.
    #[must_use]
    pub fn sent_early_data(&self) -> bool {
        self.inner.early_data.is_some()
    }

    /// Waits for the handshake and returns whether the server accepted this
    /// connection's early data, or `None` when it sent none.
    ///
    /// Once the handshake completes, the connection checks and applies the
    /// peer's TLS metadata as a connection without early data does before its
    /// first request: the `h3` ALPN, the ALPS `ACCEPT_CH` entries, and the
    /// ALPS SETTINGS. `Some(false)` also covers a connection whose metadata
    /// failed those checks, which is closed, and a connection that closed
    /// before its handshake completed.
    pub async fn early_data_accepted(&self) -> Option<bool> {
        let early_data = self.inner.early_data.as_ref()?;
        Some(early_data.outcome().await == EarlyDataOutcome::Accepted)
    }

    /// Waits for the handshake and returns whether this connection sent early
    /// data and then failed: its handshake did not complete, or its handshake
    /// metadata failed the checks a normal connection applies.
    ///
    /// Such a connection may have carried requests before its handshake, as a
    /// raced alternative that won on early data does. A connection that sent
    /// no early data, or whose early data the server accepted or rejected,
    /// returns `false`.
    pub async fn early_data_handshake_failed(&self) -> bool {
        let Some(early_data) = &self.inner.early_data else {
            return false;
        };
        matches!(
            early_data.outcome().await,
            EarlyDataOutcome::Invalid(_) | EarlyDataOutcome::Failed
        )
    }

    /// Returns whether this connection started from the server's HTTP/3
    /// SETTINGS remembered with the session ticket it presented.
    ///
    /// Only a connection that sends early data does. Until the server's own
    /// SETTINGS arrive, its requests use the remembered values, so a request
    /// under a dynamic QPACK policy can be encoded without waiting for them
    /// (RFC 9114, section 7.2.4.2). The server's SETTINGS must then stay
    /// compatible with the remembered ones; otherwise the connection closes
    /// with `H3_SETTINGS_ERROR`.
    #[must_use]
    pub fn started_from_remembered_settings(&self) -> bool {
        self.inner.remembered_settings
    }

    /// Returns whether this connection sent early data that the server has
    /// not answered yet, because its handshake is still running.
    #[must_use]
    pub fn early_data_pending(&self) -> bool {
        self.inner
            .early_data
            .as_ref()
            .is_some_and(|early_data| early_data.settled().is_none())
    }

    /// Waits until the server has answered this connection's early data.
    ///
    /// Returns `Ok` at once for a connection that sent none, and after the
    /// handshake when the handshake metadata passed the checks a normal
    /// connection applies. When the server rejected the early data, the
    /// connection first starts HTTP/3 again after the handshake, without the
    /// SETTINGS remembered with the ticket, as Chromium resends on the
    /// connection; requests sent from then on use the new session. Otherwise
    /// the error says why the connection cannot carry a request:
    ///
    /// - the handshake metadata was invalid: the error a full handshake
    ///   reports for it;
    /// - the connection closed before its handshake completed, or before
    ///   HTTP/3 started again: the connection error.
    pub async fn early_data_settled(&self) -> Result<(), Http3Error> {
        let Some(early_data) = &self.inner.early_data else {
            return Ok(());
        };
        match early_data.outcome().await {
            EarlyDataOutcome::Accepted | EarlyDataOutcome::Rejected => Ok(()),
            EarlyDataOutcome::Invalid(invalid) => Err(invalid.error()),
            EarlyDataOutcome::Failed => Err(match self.inner.quinn.close_reason() {
                Some(reason) => super::connection_error(reason),
                None => Http3Error::without_source(
                    Http3ErrorKind::Connection,
                    "HTTP/3 connection closed before its early data was answered",
                ),
            }),
        }
    }

    /// Returns whether this connection's TLS handshake resumed a session.
    ///
    /// Only connections opened by a connector from
    /// [`super::Http3Connector::with_isolated_session_cache`] can resume.
    #[must_use]
    pub fn session_resumed(&self) -> bool {
        self.inner
            .quinn
            .handshake_data()
            .and_then(|data| data.downcast::<phantom_quic_btls::HandshakeData>().ok())
            .is_some_and(|data| data.session_resumed())
    }

    /// Returns the server's `initial_max_streams_bidi` transport parameter
    /// (RFC 9000, section 18.2) once the handshake has completed.
    ///
    /// It is how many request streams the server lets this connection open
    /// before it grants more with `MAX_STREAMS` frames. A server that grants
    /// one back as each stream closes keeps this many open at once. `None`
    /// before the handshake completes, as on a connection whose early data
    /// is unanswered.
    #[must_use]
    pub fn peer_initial_max_streams_bidi(&self) -> Option<u64> {
        self.inner
            .quinn
            .handshake_data()
            .and_then(|data| data.downcast::<phantom_quic_btls::HandshakeData>().ok())
            .and_then(|data| data.peer_initial_max_streams_bidi())
    }

    #[cfg(test)]
    pub(super) async fn send_request(
        &self,
        request: Request<()>,
        body: Option<Bytes>,
    ) -> Result<Response<Http3Body>, Http3Error> {
        let request = super::prepare_request(request, body)?;
        self.send_prepared_request(request).await
    }

    pub(super) async fn send_prepared_request(
        &self,
        prepared: PreparedRequest,
    ) -> Result<Response<Http3Body>, Http3Error> {
        let early_data = match &self.inner.early_data {
            None => Some("none"),
            Some(_) if !prepared.is_replay_safe() => {
                // Early data is replayable; anything else waits for the handshake.
                self.early_data_settled().await?;
                Some("after_handshake")
            }
            // Known once the request stream opens: a QPACK policy that waits
            // for the peer's SETTINGS can hold it until the handshake ends.
            Some(_) => None,
        };
        let (result, sent_before_answer) =
            self.send_prepared_request_now(prepared, early_data).await;
        let Some(early_data) = &self.inner.early_data else {
            return result;
        };
        // A response head arrives only after the handshake completed, so the
        // outcome settles without waiting on the network.
        match (result, early_data.outcome().await) {
            // Only the discarded session's requests are unprocessed; the
            // server saw none of them (RFC 9001, section 4.6.2).
            (Err(_), EarlyDataOutcome::Rejected) if sent_before_answer => {
                debug!("HTTP/3 early data rejected; the request was not processed");
                Err(Http3Error::early_data_rejected())
            }
            (_, EarlyDataOutcome::Invalid(invalid)) => {
                debug!("HTTP/3 early-data handshake metadata is invalid; the connection closed");
                Err(invalid.error())
            }
            (result, _) => result,
        }
    }

    /// Locks the sender for one request and returns whether the server had
    /// not answered the early data yet.
    ///
    /// Quinn discards the streams of rejected early data in the same step
    /// that completes the TLS handshake. So while the answer is unpublished
    /// but the handshake has completed, the request waits for the answer and
    /// then uses the session that follows it.
    async fn lock_sender(&self) -> (MutexGuard<'_, Option<RequestSender>>, bool) {
        loop {
            let sender = self.inner.session.sender.lock().await;
            let pending = self.early_data_pending();
            if !pending || self.inner.quinn.handshake_data().is_none() {
                return (sender, pending);
            }
            drop(sender);
            if let Some(early_data) = &self.inner.early_data {
                early_data.outcome().await;
            }
        }
    }

    /// Sends one request; `early_data` names how it relates to the
    /// connection's early data for the trace: `none` on a connection that
    /// sent none, `sent` when its stream opened before the handshake
    /// completed, or `after_handshake`. `None` records `sent` or
    /// `after_handshake` once the stream opens.
    ///
    /// Also returns whether the request took the sender before the server
    /// answered the early data, so used the session a rejection discards.
    async fn send_prepared_request_now(
        &self,
        prepared: PreparedRequest,
        early_data: Option<&'static str>,
    ) -> (Result<Response<Http3Body>, Http3Error>, bool) {
        let method = prepared.method().clone();
        let body_bytes = prepared.body_len();
        let has_body = prepared.has_body();
        let span = debug_span!(
            "http3.response_head",
            method = %method,
            protocol = "h3",
            body_bytes = body_bytes.unwrap_or(0),
            body_length_known = body_bytes.is_some(),
            has_body,
            early_data = early_data,
            status = field::Empty,
            outcome = field::Empty,
        );
        let mut sent_before_answer = false;
        let result = async {
            let (request, body, trailers) = prepared.into_parts();
            let (stream, mut datagrams) = {
                let (mut sender, pending) = self.lock_sender().await;
                sent_before_answer = pending;
                let sender = sender.as_mut().ok_or_else(driver_unavailable)?;
                let stream = sender
                    .send_request(request)
                    .await
                    .map_err(Http3Error::request_open)?;
                if early_data.is_none() {
                    let sent = self.early_data_pending();
                    span.record("early_data", if sent { "sent" } else { "after_handshake" });
                }
                // Registering under the send lock keeps datagram monitors in
                // stream-ID order, which the router relies on to drop
                // datagrams for closed streams.
                let datagrams = self
                    .inner
                    .datagrams
                    .as_ref()
                    .map(|router| router.monitor(stream.id()));
                (stream, datagrams)
            };
            let mut pending = PendingRequest::new(stream);
            let mut send = RequestSend::stream(pending.take_send()?);
            let exchange_result = exchange(
                &mut send,
                pending.recv_mut()?,
                body,
                trailers,
                datagrams.as_mut(),
            )
            .await;
            let response = match exchange_result {
                Ok(response) => response,
                Err(ResponseHeadError::RequestBody(error)) => return Err(error),
                Err(ResponseHeadError::Stream(error)) => {
                    return Err(Http3Error::request_stream(error));
                }
                Err(ResponseHeadError::UnsupportedDatagram) => {
                    datagrams.take();
                    let recv = pending.into_recv()?;
                    body::defer_datagram_abort(send, recv, self.clone());
                    return Err(Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "peer sent an HTTP Datagram for a request without datagram semantics",
                    ));
                }
                Err(ResponseHeadError::SwitchingProtocols) => {
                    return Err(Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "peer sent a 101 response over HTTP/3",
                    ));
                }
                Err(ResponseHeadError::TooManyInformational) => {
                    return Err(super::too_many_informational());
                }
            };
            span.record("status", response.status().as_u16());

            let (mut parts, ()) = response.into_parts();
            let ordered_headers = parts
                .extensions
                .remove::<h3::ext::OrderedHeaders>()
                .map(|headers| {
                    crate::OrderedResponseHeaders::from_normalized_fields(headers.as_slice())
                })
                .ok_or_else(|| {
                    Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "HTTP/3 response header order was not captured",
                    )
                })?;
            parts.extensions.insert(ordered_headers);
            let recv = pending.into_recv()?;
            Ok(Response::from_parts(
                parts,
                Http3Body::new(send, recv, self.clone(), datagrams),
            ))
        }
        .instrument(span.clone())
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "error" });
        (result, sent_before_answer)
    }

    /// Opens one extended CONNECT stream after the peer enables it.
    ///
    /// No request stream is opened unless the peer's SETTINGS, from ALPS or
    /// the control stream, carry `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`
    /// (RFC 9220 section 3, RFC 8441 section 3).
    pub(super) async fn send_extended_connect(
        &self,
        protocol: Http3ExtendedProtocol,
        request: Request<()>,
    ) -> Result<Http3ExtendedConnectOutcome, Http3Error> {
        let span = debug_span!(
            "http3.extended_connect.response_head",
            method = "CONNECT",
            protocol = "h3",
            extended_protocol = protocol.trace_name(),
            status = field::Empty,
            outcome = field::Empty,
        );
        let result = async {
            self.early_data_settled().await?;
            let mut peer_settings = {
                let sender = self.inner.session.sender.lock().await;
                sender
                    .as_ref()
                    .ok_or_else(driver_unavailable)?
                    .peer_settings()
            };
            if !peer_settings.ready().await?.enable_extended_connect() {
                return Err(Http3Error::without_source(
                    Http3ErrorKind::ExtendedConnectUnavailable,
                    "HTTP/3 peer did not enable extended CONNECT",
                ));
            }
            let (stream, mut datagrams) = {
                let mut sender = self.inner.session.sender.lock().await;
                let sender = sender.as_mut().ok_or_else(driver_unavailable)?;
                let stream = sender.send_request(request).await?;
                // Registering under the send lock keeps datagram monitors in
                // stream-ID order, which the router relies on to drop
                // datagrams for closed streams.
                let datagrams = self
                    .inner
                    .datagrams
                    .as_ref()
                    .map(|router| router.monitor(stream.id()));
                (stream, datagrams)
            };
            let mut pending = PendingRequest::new(stream);
            let response = {
                let (_, recv) = pending.streams_mut()?;
                receive_response(recv, datagrams.as_mut()).await
            };
            let response = match response {
                Ok(response) => response,
                Err(ResponseHeadError::Stream(error)) => return Err(error.into()),
                Err(ResponseHeadError::UnsupportedDatagram) => {
                    datagrams.take();
                    let (send, recv) = pending.into_streams()?;
                    body::defer_datagram_abort(RequestSend::stream(send), recv, self.clone());
                    return Err(Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "peer sent an HTTP Datagram for a request without datagram semantics",
                    ));
                }
                Err(ResponseHeadError::SwitchingProtocols) => {
                    return Err(Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "peer sent a 101 response over HTTP/3",
                    ));
                }
                Err(ResponseHeadError::TooManyInformational) => {
                    return Err(super::too_many_informational());
                }
                Err(ResponseHeadError::RequestBody(error)) => return Err(error),
            };
            span.record("status", response.status().as_u16());

            let accepted = response.status().is_success();
            let (mut parts, ()) = response.into_parts();
            let ordered_headers = parts
                .extensions
                .remove::<h3::ext::OrderedHeaders>()
                .map(|headers| {
                    crate::OrderedResponseHeaders::from_normalized_fields(headers.as_slice())
                })
                .ok_or_else(|| {
                    Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "HTTP/3 response header order was not captured",
                    )
                })?;
            parts.extensions.insert(ordered_headers);
            let (mut send, recv) = pending.into_streams()?;
            if accepted {
                return Ok(Http3ExtendedConnectOutcome::Accepted {
                    response: Response::from_parts(parts, ()),
                    stream: Http3ExtendedConnectStream::new(send, recv, self.clone(), datagrams),
                });
            }
            let mut recv = recv;
            if let Err(error) = poll_fn(|context| send.poll_finish(context)).await {
                recv.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                return Err(error.into());
            }
            let body = Http3Body::new(RequestSend::stream(send), recv, self.clone(), datagrams);
            Ok(Http3ExtendedConnectOutcome::Rejected(Response::from_parts(
                parts, body,
            )))
        }
        .instrument(span.clone())
        .await;
        let outcome = match &result {
            Ok(Http3ExtendedConnectOutcome::Accepted { .. }) => "accepted",
            Ok(Http3ExtendedConnectOutcome::Rejected(_)) => "rejected",
            Err(error) if error.kind() == Http3ErrorKind::ExtendedConnectUnavailable => {
                "capability_unavailable"
            }
            Err(error) if error.kind() == Http3ErrorKind::Protocol => "protocol_error",
            Err(_) => "request_error",
        };
        span.record("outcome", outcome);
        result
    }

    /// Waits for the peer's SETTINGS from ALPS or the control stream and
    /// reports the extension capabilities they enable.
    pub(super) async fn peer_extensions(&self) -> Result<PeerExtensions, Http3Error> {
        // A rejection replaces the session, whose SETTINGS are the ones that
        // count.
        self.early_data_settled().await?;
        let mut peer_settings = {
            let sender = self.inner.session.sender.lock().await;
            sender
                .as_ref()
                .ok_or_else(driver_unavailable)?
                .peer_settings()
        };
        let settings = peer_settings.ready().await?;
        Ok(PeerExtensions {
            extended_connect: settings.enable_extended_connect(),
            datagram: settings.enable_datagram(),
        })
    }

    /// Returns the largest QUIC DATAGRAM payload currently sendable, or
    /// `None` when the peer did not advertise `max_datagram_frame_size`.
    pub(super) fn max_datagram_size(&self) -> Option<usize> {
        self.inner.quinn.max_datagram_size()
    }

    pub(super) fn quinn(&self) -> &quinn::Connection {
        &self.inner.quinn
    }

    /// Sends one RFC 9298 CONNECT-UDP request and registers its datagram flow.
    ///
    /// The caller checks peer SETTINGS first. The flow is registered under
    /// the send lock so the router keeps stream-ID order. Only a 2xx response
    /// yields the tunnel; any other final response aborts the request stream
    /// (RFC 9298 section 3.5).
    pub(super) async fn send_connect_udp(
        &self,
        request: Request<()>,
    ) -> Result<ConnectUdpExchange, Http3Error> {
        self.early_data_settled().await?;
        let router = self.inner.datagrams.as_ref().ok_or_else(|| {
            Http3Error::without_source(
                Http3ErrorKind::Configuration,
                "CONNECT-UDP requires a connection that receives HTTP Datagrams",
            )
        })?;
        let (stream, flow) = {
            let mut sender = self.inner.session.sender.lock().await;
            let sender = sender.as_mut().ok_or_else(driver_unavailable)?;
            let stream = sender.send_request(request).await?;
            let flow = router.flow(stream.id());
            (stream, flow)
        };
        let mut pending = PendingRequest::new(stream);
        let response = {
            let (_, recv) = pending.streams_mut()?;
            receive_response(recv, None).await
        };
        let response = match response {
            Ok(response) => response,
            Err(ResponseHeadError::Stream(error)) => return Err(error.into()),
            Err(ResponseHeadError::SwitchingProtocols) => {
                return Err(Http3Error::without_source(
                    Http3ErrorKind::Protocol,
                    "peer sent a 101 response over HTTP/3",
                ));
            }
            Err(ResponseHeadError::TooManyInformational) => {
                return Err(super::too_many_informational());
            }
            Err(ResponseHeadError::UnsupportedDatagram | ResponseHeadError::RequestBody(_)) => {
                return Err(driver_unavailable());
            }
        };
        let status = response.status();
        if !status.is_success() {
            return Ok(ConnectUdpExchange::Rejected {
                status,
                headers: Box::new(response.headers().clone()),
            });
        }
        // RFC 9297 section 3.2: a response that starts the Capsule Protocol
        // carries no content and is malformed with these statuses or fields.
        if matches!(status.as_u16(), 204..=206)
            || [
                http::header::CONTENT_LENGTH,
                http::header::CONTENT_TYPE,
                http::header::TRANSFER_ENCODING,
            ]
            .iter()
            .any(|name| response.headers().contains_key(name))
        {
            return Err(Http3Error::without_source(
                Http3ErrorKind::Protocol,
                "CONNECT-UDP response is malformed for the Capsule Protocol",
            ));
        }
        let (send, recv) = pending.into_streams()?;
        Ok(ConnectUdpExchange::Accepted {
            status,
            send: Box::new(send),
            recv: Box::new(recv),
            flow,
        })
    }

    pub(super) fn is_reusable(&self) -> bool {
        if self.inner.quinn.close_reason().is_some() {
            return false;
        }
        if self
            .inner
            .early_data
            .as_ref()
            .and_then(EarlyData::settled)
            .is_some_and(|outcome| {
                !matches!(
                    outcome,
                    EarlyDataOutcome::Accepted | EarlyDataOutcome::Rejected
                )
            })
        {
            return false;
        }
        if self
            .inner
            .datagrams
            .as_ref()
            .is_some_and(DatagramRouter::is_failed)
        {
            return false;
        }
        self.inner.session.is_healthy()
    }

    pub(super) fn belongs_to(&self, identity: &Arc<()>) -> bool {
        self.inner
            .connector_identity
            .as_ref()
            .is_some_and(|connection| Arc::ptr_eq(connection, identity))
    }

    pub(super) fn runtime(&self) -> &Handle {
        &self.inner.runtime
    }

    pub(super) fn record(&self, signal: DriverSignal) {
        self.inner.signal.fetch_max(signal.rank(), Ordering::AcqRel);
    }
}

/// Extension settings received from the peer.
#[derive(Clone, Copy, Debug)]
pub(super) struct PeerExtensions {
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (RFC 9220 section 3).
    pub(super) extended_connect: bool,
    /// `SETTINGS_H3_DATAGRAM = 1` (RFC 9297 section 2.1.1).
    pub(super) datagram: bool,
}

/// Final response to a CONNECT-UDP request.
pub(super) enum ConnectUdpExchange {
    // Boxed so the accepted exchange stays close in size to a rejection.
    Accepted {
        status: http::StatusCode,
        send: Box<RequestSendStream>,
        recv: Box<RequestRecvStream>,
        flow: DatagramFlow,
    },
    /// A final non-2xx response; its fields carry any proxy challenge.
    Rejected {
        status: http::StatusCode,
        headers: Box<http::HeaderMap>,
    },
}

async fn exchange(
    send: &mut RequestSend,
    recv: &mut RequestRecvStream,
    body: Option<RequestBody>,
    trailers: Option<super::request::PreparedTrailers>,
    datagrams: Option<&mut super::DatagramMonitor>,
) -> Result<Response<()>, ResponseHeadError> {
    if body.is_none() && trailers.is_none() {
        if let RequestSend::Stream(stream) = send {
            stream.finish().await.map_err(ResponseHeadError::Stream)?;
        }
        return receive_response(recv, datagrams).await;
    }

    send.start_upload(body, trailers);
    let mut response = pin!(receive_response(recv, datagrams));
    tokio::select! {
        biased;
        // RFC 9114 section 4.1: a response can precede the end of the request.
        // The upload stays in `send` and continues beside the response body.
        response = &mut response => response,
        uploaded = send.uploaded() => match uploaded {
            Ok(()) => response.await,
            Err(UploadError::Body(error)) => Err(ResponseHeadError::RequestBody(error)),
            Err(UploadError::Stream(upload_error)) => match response.await {
                Ok(response) => Ok(response),
                Err(ResponseHeadError::Stream(_)) => Err(ResponseHeadError::Stream(upload_error)),
                Err(error) => Err(error),
            },
        },
    }
}

impl std::fmt::Debug for Http3Connection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Http3Connection")
            .field("closed", &self.inner.quinn.close_reason().is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        // Dropping the last sender lets the driver close HTTP/3. A restart
        // that holds the lock at this moment drops its sender when it ends.
        if let Ok(mut sender) = self.session.sender.try_lock() {
            sender.take();
        }
        let signal = DriverSignal::from_rank(self.signal.load(Ordering::Acquire));
        self.driver.finish(signal);
    }
}
