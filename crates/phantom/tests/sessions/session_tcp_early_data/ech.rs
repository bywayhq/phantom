use std::{
    future::{Future, poll_fn},
    io,
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
};

use phantom::{
    AddressResolver, HttpAttemptBudget, RequestBuilder, TimeoutPhase,
    dns::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup, HttpsRecordResolver},
    profile::{EchGreaseSettings, EchSettings},
};
use phantom_testkit::tls::{TEST_ECH_KEYS, ech_config, ech_config_list};
use tokio::sync::watch;

use super::*;
use crate::support::ech::{ORIGIN_NAME, PUBLIC_NAME, https_rdata_with_alpn, origin_identity};

mod lifecycle;
mod peer;

#[derive(Clone, Copy)]
enum Transport {
    Http1,
    Http2,
    NegotiatedHttp1,
    NegotiatedHttp2,
}

impl Transport {
    fn alpn(self) -> &'static [u8] {
        match self {
            Self::Http1 | Self::NegotiatedHttp1 => H1_ALPN,
            Self::Http2 | Self::NegotiatedHttp2 => H2_ALPN,
        }
    }

    fn request(self, client: &Client, method: Method, uri: &str) -> TestResult<RequestBuilder> {
        Ok(match self {
            Self::Http1 => client.request(HttpProtocol::Http1, method, uri)?,
            Self::Http2 => client.request(HttpProtocol::Http2, method, uri)?,
            Self::NegotiatedHttp1 | Self::NegotiatedHttp2 => {
                client.request_negotiated(method, uri)?
            }
        })
    }
}

const TRANSPORTS: [Transport; 4] = [
    Transport::Http1,
    Transport::Http2,
    Transport::NegotiatedHttp1,
    Transport::NegotiatedHttp2,
];

#[derive(Clone, Copy)]
enum Recovery {
    Replacement,
    RemoveEch,
    SecondRejection,
    ExhaustedBudget,
    AuthenticationTimeout,
}

#[derive(Default)]
struct HookCounts {
    requests: AtomicUsize,
    responses: AtomicUsize,
    errors: AtomicUsize,
}

impl phantom::RequestHooks for HookCounts {
    fn on_request(&self, _: &phantom::RequestHookContext<'_>) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    fn on_response(&self, _: &phantom::ResponseHookContext<'_>) {
        self.responses.fetch_add(1, Ordering::Relaxed);
    }

    fn on_error(&self, _: &phantom::RequestErrorHookContext<'_>) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn authenticated_ech_retry_preserves_gets_and_one_shot_posts() -> TestResult<()> {
    for transport in TRANSPORTS {
        for method in [Method::GET, Method::POST] {
            run(transport, method, Recovery::Replacement).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn authenticated_empty_ech_retry_removes_ech_for_the_fresh_handshake() -> TestResult<()> {
    for transport in TRANSPORTS {
        run(transport, Method::GET, Recovery::RemoveEch).await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_second_authenticated_ech_rejection_is_terminal() -> TestResult<()> {
    for transport in TRANSPORTS {
        run(transport, Method::GET, Recovery::SecondRejection).await?;
    }
    Ok(())
}

#[tokio::test]
async fn exhausted_http_allowance_prevents_the_fresh_ech_connection() -> TestResult<()> {
    for transport in TRANSPORTS {
        run(transport, Method::GET, Recovery::ExhaustedBudget).await?;
    }
    Ok(())
}

#[tokio::test]
async fn deferred_ech_authentication_observes_the_connect_timeout() -> TestResult<()> {
    for transport in TRANSPORTS {
        for method in [Method::GET, Method::POST] {
            run(transport, method, Recovery::AuthenticationTimeout).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn canceling_a_one_shot_post_retires_unauthenticated_h1() -> TestResult<()> {
    for transport in [Transport::Http1, Transport::NegotiatedHttp1] {
        let mut server = None;
        let result = bounded(async {
            let identity = origin_identity()?;
            let offers = Offers::default();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let port = listener.local_addr()?.port();
            let session = discovering_client(&identity, port)?;
            let acceptor = acceptor_for(&identity, &offers, H1_ALPN)?;
            peer::set_key(&acceptor, 1, &TEST_ECH_KEYS[0])?;
            let (closed, seed_closed) = oneshot::channel();
            let (waiting, authentication_waiting) = oneshot::channel();
            server = Some(ConnectionPeer::spawn(async move {
                peer::serve_cancelled_post(listener, acceptor, transport, closed, waiting).await
            }));
            let seed = format!("https://{ORIGIN_NAME}:{port}/seed");
            transport.request(&session, Method::GET, &seed)?.send().await?
                .into_body().collect().await?;
            seed_closed.await?;

            let polls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&polls);
            let body = http_body_util::Full::new(bytes::Bytes::from_static(b"payload"))
                .map_frame(move |frame| {
                    observed.fetch_add(1, Ordering::Relaxed);
                    frame
                });
            let url = format!("https://{ORIGIN_NAME}:{port}/cancelled");
            let mut send = Box::pin(transport.request(&session, Method::POST, &url)?
                .streaming_body(body).send());
            tokio::select! {
                biased;
                _ = &mut send => return Err("unauthenticated POST finished before cancellation".into()),
                result = authentication_waiting => result?,
            }
            drop(send);
            if polls.load(Ordering::Relaxed) != 0 {
                return Err("unauthenticated POST consumed its one-shot body".into());
            }
            // Keep the pool alive: client shutdown must not hide a leaked lease.
            join(&mut server).await?;
            drop(session);
            Ok(())
        }).await;
        finish(result, server).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ech_recovery_admission_keeps_the_original_connect_deadline() -> TestResult<()> {
    for transport in [Transport::Http1, Transport::NegotiatedHttp1] {
        let mut server = None;
        let result = bounded(async {
            let identity = origin_identity()?;
            let offers = Offers::default();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let port = listener.local_addr()?.port();
            let session = discovering_client(&identity, port)?;
            let acceptor = acceptor_for(&identity, &offers, H1_ALPN)?;
            peer::set_key(&acceptor, 1, &TEST_ECH_KEYS[0])?;
            let (closed, seed_closed) = oneshot::channel();
            let (arrived, failed_connection_arrived) = oneshot::channel();
            let (reject, allow_rejection) = oneshot::channel();
            let (blocked, competing_connection_arrived) = oneshot::channel();
            server = Some(ConnectionPeer::spawn(async move {
                peer::serve_contended_admission(listener, acceptor, transport, closed,
                    arrived, allow_rejection, blocked).await
            }));
            let seed = format!("https://{ORIGIN_NAME}:{port}/seed");
            transport.request(&session, Method::GET, &seed)?.send().await?
                .into_body().collect().await?;
            seed_closed.await?;

            let url = format!("https://{ORIGIN_NAME}:{port}/recover");
            let mut recovering = Box::pin(transport.request(&session, Method::GET, &url)?
                .timeouts(RequestTimeoutOverrides::disabled()
                    .connect(TimeoutOverride::Limit(Duration::from_millis(500)))
                    .pool_admission(TimeoutOverride::Limit(Duration::from_secs(5))))
                .send());
            tokio::select! {
                biased;
                _ = &mut recovering => return Err("ECH request finished before rejection".into()),
                result = failed_connection_arrived => result?,
            }
            let url = format!("https://{ORIGIN_NAME}:{port}/competing");
            let mut competing = Box::pin(transport.request(&session, Method::POST, &url)?
                .streaming_body(http_body_util::Full::new(bytes::Bytes::from_static(b"payload")))
                .send());
            let pending = poll_fn(|context| Poll::Ready(competing.as_mut().poll(context).is_pending())).await;
            if !pending {
                return Err("competing POST did not wait for the occupied H1 admission".into());
            }
            reject.send(()).map_err(|_| "rejection peer stopped")?;
            tokio::select! {
                biased;
                _ = &mut recovering => return Err("ECH request finished before admission contention".into()),
                _ = &mut competing => return Err("competing POST finished before authentication".into()),
                result = competing_connection_arrived => result?,
            }
            let error = tokio::time::timeout(Duration::from_secs(2), &mut recovering).await?
                .err().ok_or("ECH recovery ignored its original Connect deadline")?;
            if error.timeout_phase() != Some(TimeoutPhase::Connect) {
                return Err("ECH recovery admission used the wrong deadline".into());
            }
            drop((recovering, competing));
            join(&mut server).await?;
            drop(session);
            Ok(())
        }).await;
        finish(result, server).await?;
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_h2_requests_share_one_fresh_ech_connection() -> TestResult<()> {
    for transport in [Transport::Http2, Transport::NegotiatedHttp2] {
        let mut server = None;
        let result = bounded(async {
            let identity = origin_identity()?;
            let offers = Offers::default();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let port = listener.local_addr()?.port();
            let session = discovering_client(&identity, port)?;
            let acceptor = acceptor_for(&identity, &offers, H2_ALPN)?;
            peer::set_key(&acceptor, 1, &TEST_ECH_KEYS[0])?;
            let (closed, seed_closed) = oneshot::channel();
            server = Some(ConnectionPeer::spawn(async move {
                peer::serve_shared(listener, acceptor, transport, closed).await
            }));
            let seed = format!("https://{ORIGIN_NAME}:{port}/seed");
            transport
                .request(&session, Method::GET, &seed)?
                .send()
                .await?
                .into_body()
                .collect()
                .await?;
            seed_closed.await?;
            let budget = HttpAttemptBudget::new(4);
            let first = format!("https://{ORIGIN_NAME}:{port}/first");
            let second = format!("https://{ORIGIN_NAME}:{port}/second");
            let send = |uri| {
                let request = transport
                    .request(&session, Method::GET, uri)
                    .map(|request| request.attempt_budget(budget.clone()));
                async move {
                    request?.send().await?.into_body().collect().await?;
                    TestResult::<()>::Ok(())
                }
            };
            let (first, second) = tokio::join!(send(&first), send(&second));
            finish_with_cleanup(first, second)?;
            if budget.remaining() > 1 {
                return Err("concurrent requests did not admit an ECH replacement".into());
            }
            drop(session);
            join(&mut server).await?;
            if offers.take().last() != Some(&FRESH) {
                return Err("shared ECH recovery did not use a full handshake".into());
            }
            Ok(())
        })
        .await;
        finish(result, server).await?;
    }
    Ok(())
}

async fn run(transport: Transport, method: Method, recovery: Recovery) -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = origin_identity()?;
        let offers = Offers::default();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let session = discovering_client(&identity, port)?;
        let acceptor = acceptor_for(&identity, &offers, transport.alpn())?;
        let plain = acceptor_for(&identity, &offers, transport.alpn())?;
        peer::set_key(&acceptor, 1, &TEST_ECH_KEYS[0])?;
        let (closed, seed_closed) = oneshot::channel();
        let server_method = method.clone();
        server = Some(ConnectionPeer::spawn(async move {
            peer::serve(
                listener,
                acceptor,
                plain,
                transport,
                server_method,
                recovery,
                closed,
            )
            .await
        }));
        let seed = format!("https://{ORIGIN_NAME}:{port}/seed");
        transport
            .request(&session, Method::GET, &seed)?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        seed_closed.await?;

        let allowance = if matches!(recovery, Recovery::ExhaustedBudget) {
            1
        } else {
            2
        };
        let budget = HttpAttemptBudget::new(allowance);
        let url = format!("https://{ORIGIN_NAME}:{port}/recovered");
        let hooks = Arc::new(HookCounts::default());
        let header_calls = Arc::new(AtomicUsize::new(0));
        let observed_headers = Arc::clone(&header_calls);
        let mut request = transport
            .request(&session, method.clone(), &url)?
            .request_hooks(Arc::clone(&hooks))
            .header_hook(move |headers| {
                let call = observed_headers.fetch_add(1, Ordering::Relaxed);
                let value = if call == 0 { "original" } else { "changed" };
                headers.append(phantom::RequestHeader::new("x-frozen", value))
            })
            .attempt_budget(budget.clone());
        if method == Method::POST {
            request = request.streaming_body(http_body_util::Full::new(bytes::Bytes::from_static(
                b"payload",
            )));
        }
        if matches!(recovery, Recovery::AuthenticationTimeout) {
            request = request.timeouts(
                RequestTimeoutOverrides::disabled()
                    .connect(TimeoutOverride::Limit(Duration::from_millis(150))),
            );
        }
        let response = request.send().await;
        let succeeded = usize::from(response.is_ok());
        if hooks.requests.load(Ordering::Relaxed) != 1
            || hooks.responses.load(Ordering::Relaxed) != succeeded
            || hooks.errors.load(Ordering::Relaxed) != 1 - succeeded
            || header_calls.load(Ordering::Relaxed) != 1
        {
            return Err(
                "ECH recovery reran a logical hook or omitted its terminal callback".into(),
            );
        }
        match recovery {
            Recovery::Replacement | Recovery::RemoveEch => {
                let response = response?;
                if response.status() != StatusCode::OK {
                    return Err("recovered request returned the wrong status".into());
                }
                response.into_body().collect().await?;
                if budget.remaining() != 0 {
                    return Err(
                        "deferred ECH recovery did not admit its replacement HTTP attempt".into(),
                    );
                }
            }
            Recovery::SecondRejection => {
                let error = response.err().ok_or("second ECH rejection succeeded")?;
                if error.kind() != RequestErrorKind::Tls || !has_ech_rejection(&error) {
                    return Err("second rejection lost its typed authenticated ECH failure".into());
                }
            }
            Recovery::ExhaustedBudget => {
                let error = response
                    .err()
                    .ok_or("ECH recovery exceeded its HTTP allowance")?;
                if error.kind() != RequestErrorKind::AttemptBudgetExhausted {
                    return Err("exhausted ECH recovery returned the wrong error kind".into());
                }
            }
            Recovery::AuthenticationTimeout => {
                let error = response
                    .err()
                    .ok_or("deferred authentication ignored its deadline")?;
                if error.kind() != RequestErrorKind::Timeout
                    || error.timeout_phase() != Some(TimeoutPhase::Connect)
                {
                    return Err(
                        "deferred authentication did not report the connect deadline".into(),
                    );
                }
            }
        }
        if matches!(recovery, Recovery::AuthenticationTimeout)
            && matches!(transport, Transport::Http1 | Transport::NegotiatedHttp1)
        {
            // A canceled H1 setup must close while the client still exists.
            join(&mut server).await?;
            drop(session);
        } else {
            drop(session);
            join(&mut server).await?;
        }
        if matches!(recovery, Recovery::Replacement | Recovery::RemoveEch)
            && offers.take().last() != Some(&FRESH)
        {
            return Err(
                "ECH recovery offered a PSK or early data instead of a full handshake".into(),
            );
        }
        Ok(())
    })
    .await;
    finish(result, server).await
}

fn has_ech_rejection(error: &(dyn Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(error) = source {
        if error
            .downcast_ref::<phantom_net::TlsError>()
            .is_some_and(|error| error.ech_failure() == Some(phantom_net::EchFailure::Rejected))
        {
            return true;
        }
        source = error.source();
    }
    false
}

fn discovering_client(identity: &TestIdentity, port: u16) -> TestResult<Client> {
    discovering_client_with_slots(identity, port, NonZeroUsize::MIN)
}

fn discovering_client_with_slots(
    identity: &TestIdentity,
    port: u16,
    http1_connections: NonZeroUsize,
) -> TestResult<Client> {
    let configs = ech_config_list(&[ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME)]);
    let record = HttpsRecord::from_rdata(&https_rdata_with_alpn(&[b"h2", b"http/1.1"], &configs))?;
    let records = HttpsRecordLookup::new(
        vec![HttpsRecordAnswer::new(
            format!("_{port}._https.{ORIGIN_NAME}"),
            300,
            record,
        )],
        None,
    );
    let (published, ready) = watch::channel(false);
    let https = HttpsRecordResolver::from_fn(move |_, _| {
        let published = published.clone();
        let records = records.clone();
        async move {
            published.send_replace(true);
            Ok(records)
        }
    });
    let addresses = AddressResolver::from_fn(move |_| {
        let mut ready = ready.clone();
        async move {
            while !*ready.borrow_and_update() {
                ready
                    .changed()
                    .await
                    .map_err(|_| io::Error::other("HTTPS publisher ended"))?;
            }
            Ok(vec![Ipv4Addr::LOCALHOST.into()])
        }
    });
    let mut tls = firefox::v157_tcp_tls();
    tls.ech = EchSettings::HttpsRecords(EchGreaseSettings::backend_default());
    let mut http1 = firefox::v157_http1();
    http1.max_connections_per_origin = http1_connections;
    let profile = ClientProfile::new(tls)
        .with_http1(http1)
        .with_http2(firefox::v157_http2());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN)
        .https_record_discovery(https)
        .dns_resolver(addresses)
        .build()?)
}
