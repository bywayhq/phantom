//! Encrypted Client Hello from an HTTPS DNS record, through the client facade.

use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use btls::ssl::SslAcceptor;
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProxy, Route,
    dns::HttpsRecordResolver,
    profile::{ClientProfile, browser::chrome},
};
use phantom_testkit::{
    dns::{DnsAnswer, DnsReply, DnsServer},
    tls::{TEST_ECH_KEYS, ech_config, ech_config_list},
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{Barrier, watch},
    task::{AbortHandle, JoinError},
    time::{Instant, timeout, timeout_at},
};
use tokio_btls::SslStream;

use crate::support::ech as ech_support;
use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;
use crate::support::tunnel_proxy;
// `tunnel_proxy` reaches the TLS helpers as `super::tls`.

use ech_support::{
    EchDeadline, ORIGIN_NAME, Observed, PUBLIC_NAME, Replayed, STAND_IN_NAME, TEST_TIMEOUT,
    discovering_client, ech_tls_settings, handshake, https_rdata,
};
use h3_support::client_settings;
use tls_support::{H1_ALPN, TestIdentity, TestResult, read_head};
use tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

const PARALLEL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

struct ParallelOrigin {
    peer: ConnectionPeer<TestResult<(Vec<Observed>, Vec<Observed>)>>,
    shutdown: watch::Sender<bool>,
}

impl ParallelOrigin {
    fn abort_handle(&self) -> AbortHandle {
        self.peer.abort_handle()
    }

    fn is_finished(&self) -> bool {
        self.peer.is_finished()
    }

    async fn stop(mut self) -> TestResult<()> {
        self.shutdown.send_replace(true);

        match timeout(PARALLEL_CLEANUP_TIMEOUT, &mut self.peer).await {
            Ok(Ok(result)) => result.map(|_| ()),
            Ok(Err(error)) => Err(error.into()),
            Err(error) => finish_with_cleanup(Err(error.into()), self.peer.stop().await),
        }
    }
}

impl Future for ParallelOrigin {
    type Output = Result<TestResult<(Vec<Observed>, Vec<Observed>)>, JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().peer).poll(context)
    }
}

fn client(identity: &TestIdentity, dns: &DnsServer) -> TestResult<Client> {
    client_with(
        identity,
        dns,
        ClientProfile::new(ech_tls_settings())
            .with_http2(chrome::v154_http2())
            .with_http3(client_settings()),
    )
}

fn client_with(
    identity: &TestIdentity,
    dns: &DnsServer,
    profile: ClientProfile,
) -> TestResult<Client> {
    discovering_client(identity, dns, profile, None)
}

/// An HTTP/1.1 origin that decrypts ECH under configuration 1.
fn ech_acceptor(identity: &TestIdentity) -> TestResult<SslAcceptor> {
    ech_support::ech_acceptor(identity, H1_ALPN, 1, &TEST_ECH_KEYS[0])
}

/// Serves `connections` HTTP/1.1 connections, one response each.
async fn serve(
    listener: TcpListener,
    acceptor: SslAcceptor,
    connections: usize,
) -> TestResult<Vec<Observed>> {
    serve_observed(listener, acceptor, connections, None).await
}

fn spawn_origin(
    listener: TcpListener,
    acceptor: SslAcceptor,
    connections: usize,
) -> ConnectionPeer<TestResult<Vec<Observed>>> {
    spawn_observed_origin(listener, acceptor, connections, None)
}

fn spawn_observed_origin(
    listener: TcpListener,
    acceptor: SslAcceptor,
    connections: usize,
    observation: Option<owner_contract::OriginObservation>,
) -> ConnectionPeer<TestResult<Vec<Observed>>> {
    ConnectionPeer::spawn(serve_observed(listener, acceptor, connections, observation))
}

async fn serve_observed(
    listener: TcpListener,
    acceptor: SslAcceptor,
    connections: usize,
    mut observation: Option<owner_contract::OriginObservation>,
) -> TestResult<Vec<Observed>> {
    let mut observed = Vec::new();
    for _ in 0..connections {
        let (tcp, _) = timeout(TEST_TIMEOUT, listener.accept()).await??;
        let pending = if observed.len() == 1 {
            observation
                .as_mut()
                .and_then(|observation| observation.pending_handshake.take())
        } else {
            None
        };

        let handshake = handshake(tcp, &acceptor);
        let (seen, mut tls) = match pending {
            Some(pending) => owner_contract::observe_pending_handshake(handshake, pending).await?,
            None => handshake.await?,
        };

        observed.push(seen);
        respond(&mut tls).await?;
    }
    Ok(observed)
}

/// Serves `connections` connections at once, answering none until every
/// one has sent its request, so each request needs its own connection.
async fn serve_parallel(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    connections: usize,
    shutdown: &mut watch::Receiver<bool>,
) -> TestResult<Vec<Observed>> {
    serve_parallel_observed(listener, acceptor, connections, None, None, shutdown).await
}

async fn serve_parallel_observed(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    connections: usize,
    mut observation: Option<parallel_contract::ParallelObservation>,
    prime_started: Option<watch::Sender<Option<AbortHandle>>>,
    shutdown: &mut watch::Receiver<bool>,
) -> TestResult<Vec<Observed>> {
    let barrier = Arc::new(Barrier::new(connections));
    let mut tasks = Vec::new();

    let setup = async {
        for index in 0..connections {
            let accept = listener.accept();
            let pending = observation.as_mut().and_then(|observation| {
                (index == 1)
                    .then(|| observation.pending_accept.take())
                    .flatten()
            });

            let (tcp, _) = match pending {
                Some(pending) => {
                    timeout(
                        TEST_TIMEOUT,
                        parallel_contract::observe_pending(accept, pending),
                    )
                    .await???
                }
                None => timeout(TEST_TIMEOUT, accept).await??,
            };

            let acceptor = acceptor.clone();
            let barrier = Arc::clone(&barrier);
            let mut worker = observation
                .as_mut()
                .and_then(parallel_contract::ParallelObservation::next_worker);
            let started = worker
                .as_ref()
                .map(|worker| worker.started.clone())
                .or_else(|| prime_started.clone());

            let task = ConnectionPeer::spawn(async move {
                let (seen, mut tls) = handshake(tcp, &acceptor).await?;
                let head = read_head(&mut tls).await?;
                if let Some(worker) = &mut worker {
                    worker.record_head(head, &seen)?;
                    worker.wait_at_barrier(&barrier).await?;
                    worker.respond(&mut tls).await?;
                    worker.outcome()?;
                } else {
                    barrier.wait().await;
                    write_response(&mut tls).await?;
                }

                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(seen)
            });
            if let Some(started) = started {
                drop(started.send_replace(Some(task.abort_handle())));
            }
            tasks.push(task);
        }

        if let Some(collect_after) = observation.and_then(|observation| observation.collect_after) {
            collect_after.await?;
        }
        TestResult::Ok(false)
    };

    let setup = tokio::select! {
        biased;
        result = shutdown.wait_for(|stopping| *stopping) => {
            result.map(|_| true).map_err(Into::into)
        }
        result = setup => result,
    };

    match setup {
        Ok(stopping) => collect_parallel_workers(tasks, stopping, shutdown).await,
        Err(error) => finish_with_cleanup(
            Err(error),
            collect_parallel_workers(tasks, true, shutdown)
                .await
                .map(|_| ()),
        ),
    }
}

fn abort_parallel_workers(tasks: &mut [(ConnectionPeer<TestResult<Observed>>, bool)]) {
    for (task, requested_abort) in tasks {
        if !task.is_finished() {
            task.abort();
            *requested_abort = true;
        }
    }
}

async fn collect_parallel_workers(
    tasks: Vec<ConnectionPeer<TestResult<Observed>>>,
    mut stopping: bool,
    shutdown: &mut watch::Receiver<bool>,
) -> TestResult<Vec<Observed>> {
    let mut tasks = tasks
        .into_iter()
        .map(|task| (task, false))
        .collect::<Vec<_>>();
    let mut deadline = if stopping {
        abort_parallel_workers(&mut tasks);
        Instant::now() + PARALLEL_CLEANUP_TIMEOUT
    } else {
        Instant::now() + TEST_TIMEOUT
    };

    let mut tasks = tasks.into_iter();
    let mut observed = Vec::new();
    let mut outcome: TestResult<()> = Ok(());

    while let Some((mut task, mut requested_abort)) = tasks.next() {
        let joined = if task.is_finished() {
            Ok((&mut task).await)
        } else if stopping {
            timeout_at(deadline, &mut task).await
        } else {
            tokio::select! {
                biased;
                changed = async { shutdown.wait_for(|stopping| *stopping).await.map(|_| ()) } => {
                    outcome = finish_with_cleanup(outcome, changed.map_err(Into::into));

                    if !task.is_finished() {
                        task.abort();
                        requested_abort = true;
                    }
                    abort_parallel_workers(tasks.as_mut_slice());
                    stopping = true;
                    deadline = Instant::now() + PARALLEL_CLEANUP_TIMEOUT;
                    timeout_at(deadline, &mut task).await
                }
                result = timeout_at(deadline, &mut task) => result,
            }
        };
        let result = match joined {
            Ok(Ok(result)) => result.map(Some),
            Ok(Err(error)) if requested_abort && error.is_cancelled() => Ok(None),
            Ok(Err(error)) => Err(error.into()),
            Err(error) => {
                let cleanup = if task.is_finished() {
                    match (&mut task).await {
                        Ok(result) => result.map(|_| ()),
                        Err(error) if requested_abort && error.is_cancelled() => Ok(()),
                        Err(error) => Err(error.into()),
                    }
                } else {
                    Ok(())
                };
                finish_with_cleanup::<()>(Err(error.into()), cleanup).map(|()| None)
            }
        };

        match result {
            Ok(Some(seen)) => observed.push(seen),
            Ok(None) => {}
            Err(error) => {
                let first_failure = outcome.is_ok();
                outcome = finish_with_cleanup(outcome, Err(error));

                abort_parallel_workers(tasks.as_mut_slice());
                if first_failure && !stopping {
                    deadline = Instant::now() + PARALLEL_CLEANUP_TIMEOUT;
                }
                stopping = true;
            }
        }
    }

    outcome?;

    Ok(observed)
}

fn spawn_parallel_origin(
    listener: TcpListener,
    acceptor: SslAcceptor,
    connections: usize,
    observation: Option<parallel_contract::ParallelObservation>,
    lifetime: Option<parallel_contract::Lifetime>,
) -> ParallelOrigin {
    let (shutdown, mut stopping) = watch::channel(false);
    let peer = ConnectionPeer::spawn(async move {
        let _lifetime = lifetime;
        let prime = match observation.as_ref() {
            Some(observation) => {
                serve_parallel_observed(
                    &listener,
                    &acceptor,
                    1,
                    None,
                    Some(observation.prime_started.clone()),
                    &mut stopping,
                )
                .await?
            }
            None => serve_parallel(&listener, &acceptor, 1, &mut stopping).await?,
        };
        let parallel = serve_parallel_observed(
            &listener,
            &acceptor,
            connections,
            observation,
            None,
            &mut stopping,
        )
        .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((prime, parallel))
    });
    ParallelOrigin { peer, shutdown }
}

async fn collect_parallel_requests<F>(requests: Vec<F>) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    let mut outcome = Ok(());
    for result in futures_join_all(requests).await {
        outcome = finish_with_cleanup(outcome, result);
    }

    outcome
}

async fn finish_parallel_operation(
    mut server: ParallelOrigin,
    operation: impl Future<Output = TestResult<()>>,
) -> TestResult<(Vec<Observed>, Vec<Observed>)> {
    match operation.await {
        Ok(()) => match timeout(TEST_TIMEOUT, &mut server).await {
            Ok(result) => result?,
            Err(error) => finish_with_cleanup(Err(error.into()), server.stop().await),
        },
        Err(error) => finish_with_cleanup(Err(error), server.stop().await),
    }
}

async fn respond(tls: &mut SslStream<Replayed>) -> TestResult<()> {
    read_head(tls).await?;
    write_response(tls).await
}

async fn write_response(tls: &mut SslStream<Replayed>) -> TestResult<()> {
    tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
        .await?;
    tls.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_known_record_encrypts_the_client_hello_to_the_origin() -> TestResult<()> {
    bounded(async {
        let identity =
            TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), ORIGIN_NAME)?;
        let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
        let rdata = https_rdata(&ech_config_list(std::slice::from_ref(&config)));
        let dns = DnsServer::spawn(move |_| {
            DnsReply::new(DnsAnswer::Records {
                ttl: 300,
                rdata: vec![rdata.clone()],
            })
        })
        .await?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let server = spawn_origin(listener, ech_acceptor(&identity)?, 2);
        let client = client(&identity, &dns)?;

        for path in ["/first", "/second"] {
            let response = client
                .get_negotiated(&format!("https://{ORIGIN_NAME}:{port}{path}"))?
                .send()
                .await?;
            response.into_body().collect().await?;
            // The first connection may or may not see the lookup, depending
            // on how fast the loopback resolver answers; the second one
            // finds it cached.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let observed = server.await??;
        let second = &observed[1];
        assert_eq!(second.outer_server_name.as_deref(), Some(PUBLIC_NAME));
        assert!(second.ech_accepted);
        assert_eq!(second.inner_server_name.as_deref(), Some(ORIGIN_NAME));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_profile_without_the_field_keeps_ech_grease() -> TestResult<()> {
    bounded(async {
        let identity =
            TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), ORIGIN_NAME)?;
        let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
        let rdata = https_rdata(&ech_config_list(std::slice::from_ref(&config)));
        let dns = DnsServer::spawn(move |_| {
            DnsReply::new(DnsAnswer::Records {
                ttl: 300,
                rdata: vec![rdata.clone()],
            })
        })
        .await?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let server = spawn_origin(listener, ech_acceptor(&identity)?, 2);

        let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
        let resolver = HttpsRecordResolver::from_fn(move |_, port| {
            let upstream = upstream.clone();
            async move { upstream.lookup(STAND_IN_NAME, port).await }
        });
        let mut settings = ech_tls_settings();
        settings.ech = phantom_profile::EchSettings::Grease(
            phantom_profile::EchGreaseSettings::backend_default(),
        );
        let profile = ClientProfile::new(settings)
            .with_http2(chrome::v154_http2())
            .with_http3(client_settings());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .alt_svc(NonZeroUsize::MIN.saturating_add(7))
            .https_record_discovery(resolver)
            .build()?;

        for path in ["/first", "/second"] {
            let response = client
                .get_negotiated(&format!("https://{ORIGIN_NAME}:{port}{path}"))?
                .send()
                .await?;
            response.into_body().collect().await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        for connection in server.await?? {
            assert_eq!(connection.outer_server_name.as_deref(), Some(ORIGIN_NAME));
            assert!(!connection.ech_accepted);
        }
        Ok(())
    })
    .await
}

/// Parallel negotiated HTTP/1.1 connections each offer the record's `ech`:
/// once the lookup is cached, none of them waits for it.
#[tokio::test]
async fn parallel_http1_connections_each_offer_the_cached_configuration() -> TestResult<()> {
    bounded(async {
        let identity =
            TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), ORIGIN_NAME)?;
        let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
        let rdata = https_rdata(&ech_config_list(std::slice::from_ref(&config)));
        let dns = DnsServer::spawn(move |_| {
            DnsReply::new(DnsAnswer::Records {
                ttl: 300,
                rdata: vec![rdata.clone()],
            })
        })
        .await?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let acceptor = ech_acceptor(&identity)?;
        let profile = ClientProfile::new(ech_tls_settings())
            .with_http2(chrome::v154_http2())
            .with_http3(client_settings())
            .with_http1(chrome::v154_http1());
        let client = client_with(&identity, &dns, profile)?;
        let url = |path: &str| format!("https://{ORIGIN_NAME}:{port}{path}");

        // Prime the cache: the lookup starts with this request.
        let server = spawn_parallel_origin(listener, acceptor, 3, None, None);
        let operation = async {
            let response = client.get_negotiated(&url("/prime"))?.send().await?;
            response.into_body().collect().await?;
            tokio::time::sleep(Duration::from_millis(200)).await;

            let requests = (0..3)
                .map(|index| {
                    let request = client.get_negotiated(&url(&format!("/parallel-{index}")));
                    async move {
                        let response = request?.send().await?;
                        response.into_body().collect().await?;
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                    }
                })
                .collect::<Vec<_>>();
            collect_parallel_requests(requests).await
        };
        let (_, observed) = finish_parallel_operation(server, operation).await?;
        assert_eq!(observed.len(), 3);
        for connection in &observed {
            assert_eq!(connection.outer_server_name.as_deref(), Some(PUBLIC_NAME));
            assert!(connection.ech_accepted);
            assert_eq!(connection.inner_server_name.as_deref(), Some(ORIGIN_NAME));
        }
        Ok(())
    })
    .await
}

/// Runs `futures` concurrently on the current task and returns their
/// results in order.
async fn futures_join_all<F: std::future::Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut pinned = futures.into_iter().map(Box::pin).collect::<Vec<_>>();
    let mut results = (0..pinned.len()).map(|_| None).collect::<Vec<_>>();
    std::future::poll_fn(|context| {
        let mut pending = false;
        for (index, future) in pinned.iter_mut().enumerate() {
            if results[index].is_none() {
                match future.as_mut().poll(context) {
                    Poll::Ready(output) => results[index] = Some(output),
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    results.into_iter().flatten().collect()
}

/// A request through an HTTP proxy sends no HTTPS query and offers no ECH,
/// as Chrome does: a proxied request's DNS happens at the proxy.
#[tokio::test]
async fn a_proxied_request_sends_the_origin_name_without_ech() -> TestResult<()> {
    bounded(async {
        let identity =
            TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), ORIGIN_NAME)?;
        let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
        let rdata = https_rdata(&ech_config_list(std::slice::from_ref(&config)));
        let dns = DnsServer::spawn(move |_| {
            DnsReply::new(DnsAnswer::Records {
                ttl: 300,
                rdata: vec![rdata.clone()],
            })
        })
        .await?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        let server =
            tunnel_proxy::ConnectionPeer::spawn(serve(listener, ech_acceptor(&identity)?, 1));
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tunnel_proxy::ConnectionPeer::spawn(tunnel_proxy::http1_connect(
            proxy_listener,
            origin,
        ));

        let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
        let resolver = HttpsRecordResolver::from_fn(move |_, port| {
            let upstream = upstream.clone();
            async move { upstream.lookup(STAND_IN_NAME, port).await }
        });
        let profile = ClientProfile::new(ech_tls_settings())
            .with_http2(chrome::v154_http2())
            .with_http3(client_settings());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .alt_svc(NonZeroUsize::MIN.saturating_add(7))
            .https_record_discovery(resolver)
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{proxy_address}"
            ))?))
            .build()?;

        let response = client
            .get_negotiated(&format!("https://{ORIGIN_NAME}:{}/", origin.port()))?
            .send()
            .await?;
        response.into_body().collect().await?;

        proxy.await??.cancel().await?;
        let observed = server.await??;
        assert_eq!(observed[0].outer_server_name.as_deref(), Some(ORIGIN_NAME));
        assert!(!observed[0].ech_accepted);
        assert!(dns.queries().is_empty());
        Ok(())
    })
    .await
}

async fn bounded(test: impl Future<Output = TestResult<()>>) -> TestResult<()> {
    timeout(TEST_TIMEOUT, test)
        .await
        .map_err(EchDeadline::from)?
}

mod deadline_contract;
mod owner_contract;
mod parallel_contract;
