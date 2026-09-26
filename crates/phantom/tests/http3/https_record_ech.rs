//! Encrypted Client Hello from an HTTPS DNS record, through the client facade.

use crate::support::ech as ech_support;
use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;
use crate::support::tunnel_proxy;
// `tunnel_proxy` reaches the TLS helpers as `super::tls`.

use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use btls::ssl::SslAcceptor;
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProxy, Route,
    dns::HttpsRecordResolver,
    profile::{ClientProfile, chromium},
};
use phantom_testkit::{
    dns::{DnsAnswer, DnsReply, DnsServer},
    tls::{TEST_ECH_KEYS, ech_config, ech_config_list},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::Barrier, time::timeout};
use tokio_btls::SslStream;

use ech_support::{
    ORIGIN_NAME, Observed, PUBLIC_NAME, Replayed, STAND_IN_NAME, TEST_TIMEOUT, discovering_client,
    ech_tls_settings, handshake, https_rdata,
};
use h3_support::client_settings;
use tls_support::{H1_ALPN, TestIdentity, TestResult, read_head};

fn client(identity: &TestIdentity, dns: &DnsServer) -> TestResult<Client> {
    client_with(
        identity,
        dns,
        ClientProfile::new(ech_tls_settings())
            .with_http2(chromium::v154_http2())
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
    let mut observed = Vec::new();
    for _ in 0..connections {
        let (tcp, _) = timeout(TEST_TIMEOUT, listener.accept()).await??;
        let (seen, mut tls) = handshake(tcp, &acceptor).await?;
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
) -> TestResult<Vec<Observed>> {
    let barrier = Arc::new(Barrier::new(connections));
    let mut tasks = Vec::new();
    for _ in 0..connections {
        let (tcp, _) = timeout(TEST_TIMEOUT, listener.accept()).await??;
        let acceptor = acceptor.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let (seen, mut tls) = handshake(tcp, &acceptor).await?;
            read_head(&mut tls).await?;
            barrier.wait().await;
            write_response(&mut tls).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(seen)
        }));
    }
    let mut observed = Vec::new();
    for task in tasks {
        observed.push(task.await??);
    }
    Ok(observed)
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
    timeout(TEST_TIMEOUT, async {
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
        let server = tokio::spawn(serve(listener, ech_acceptor(&identity)?, 2));
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
    .map_err(|_| "ECH test exceeded its deadline")?
}

#[tokio::test]
async fn a_profile_without_the_field_keeps_ech_grease() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
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
        let server = tokio::spawn(serve(listener, ech_acceptor(&identity)?, 2));

        let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
        let resolver = HttpsRecordResolver::from_fn(move |_, port| {
            let upstream = upstream.clone();
            async move { upstream.lookup(STAND_IN_NAME, port).await }
        });
        let mut settings = ech_tls_settings();
        settings.ech_from_https_records = false;
        let profile = ClientProfile::new(settings)
            .with_http2(chromium::v154_http2())
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
    .map_err(|_| "ECH test exceeded its deadline")?
}

/// Parallel negotiated HTTP/1.1 connections each offer the record's `ech`:
/// once the lookup is cached, none of them waits for it.
#[tokio::test]
async fn parallel_http1_connections_each_offer_the_cached_configuration() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
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
            .with_http2(chromium::v154_http2())
            .with_http3(client_settings())
            .with_http1(chromium::v154_http1());
        let client = client_with(&identity, &dns, profile)?;
        let url = |path: &str| format!("https://{ORIGIN_NAME}:{port}{path}");

        // Prime the cache: the lookup starts with this request.
        let server = tokio::spawn(async move {
            let prime = serve_parallel(&listener, &acceptor, 1).await?;
            let parallel = serve_parallel(&listener, &acceptor, 3).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((prime, parallel))
        });
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
        for result in futures_join_all(requests).await {
            result?;
        }

        let (_, observed) = server.await??;
        assert_eq!(observed.len(), 3);
        for connection in &observed {
            assert_eq!(connection.outer_server_name.as_deref(), Some(PUBLIC_NAME));
            assert!(connection.ech_accepted);
            assert_eq!(connection.inner_server_name.as_deref(), Some(ORIGIN_NAME));
        }
        Ok(())
    })
    .await
    .map_err(|_| "ECH test exceeded its deadline")?
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
    timeout(TEST_TIMEOUT, async {
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
        let server = tokio::spawn(serve(listener, ech_acceptor(&identity)?, 1));
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(tunnel_proxy::http1_connect(proxy_listener, origin));

        let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
        let resolver = HttpsRecordResolver::from_fn(move |_, port| {
            let upstream = upstream.clone();
            async move { upstream.lookup(STAND_IN_NAME, port).await }
        });
        let profile = ClientProfile::new(ech_tls_settings())
            .with_http2(chromium::v154_http2())
            .with_http3(client_settings());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .alt_svc(NonZeroUsize::MIN.saturating_add(7))
            .https_record_discovery(resolver)
            .route(Route::http_connect(HttpProxy::new(&format!(
                "http://{proxy_address}"
            ))?))
            .build()?;

        let response = client
            .get_negotiated(&format!("https://{ORIGIN_NAME}:{}/", origin.port()))?
            .send()
            .await?;
        response.into_body().collect().await?;

        proxy.await??;
        let observed = server.await??;
        assert_eq!(observed[0].outer_server_name.as_deref(), Some(ORIGIN_NAME));
        assert!(!observed[0].ech_accepted);
        assert!(dns.queries().is_empty());
        Ok(())
    })
    .await
    .map_err(|_| "ECH test exceeded its deadline")?
}
