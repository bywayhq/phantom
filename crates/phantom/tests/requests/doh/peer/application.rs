use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    time::Duration,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol,
    dns::{DnsOverHttps, DohAddressFamilies, DohConfiguration, DohMethod},
    profile::{ClientProfile, DnsCacheSettings, browser::chrome},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, task::JoinSet, time::timeout};

use crate::support::{
    tls::{
        H1_ALPN, TestIdentity, TestResult, accept_tls_stream, is_peer_gone, read_head, tls_settings,
    },
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::{
    scripted::{Peer, Reply},
    wire::Question,
};

pub(crate) struct Application {
    pub(crate) client: Client,
    pub(crate) doh: DnsOverHttps,
    pub(crate) url: String,
    origin: ConnectionPeer<TestResult<()>>,
    stop: Option<oneshot::Sender<()>>,
}

impl Application {
    pub(crate) async fn start(
        identity: &TestIdentity,
        dns_port: u16,
        families: DohAddressFamilies,
        lookup_timeout: Duration,
        cache: bool,
        dual_origin: bool,
    ) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let ipv6 = if dual_origin {
            Some(TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await?)
        } else {
            None
        };
        let origin_identity = TestIdentity::generate_for_dns("application.test")?;
        let acceptor = origin_identity.acceptor(H1_ALPN)?;
        let configuration = DohConfiguration::new(
            format!("https://resolver.test:{dns_port}/dns-query"),
            [Ipv4Addr::LOCALHOST.into()],
            DohMethod::Post,
            families,
            lookup_timeout,
            NonZeroUsize::MIN,
        );
        let profile = ClientProfile::new(tls_settings()).with_http2(chrome::v154_http2());
        let doh = DnsOverHttps::builder(profile, configuration)?
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let mut tls = tls_settings();
        tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
        let mut builder = Client::builder(ClientProfile::new(tls))
            .add_root_certificate_der(origin_identity.root_der)
            .dns_resolver(doh.address_resolver());
        if cache {
            builder = builder.dns_cache(DnsCacheSettings {
                max_entries: NonZeroUsize::MIN,
                ttl: Duration::from_secs(60),
                min_record_ttl: Duration::from_secs(60),
                negative_ttl: Some(Duration::from_secs(60)),
            });
        } else {
            builder = builder.no_dns_cache();
        }
        let client = builder.build()?;
        let (stop, mut stopped) = oneshot::channel();
        let origin = ConnectionPeer::spawn(async move {
            let mut workers = JoinSet::new();
            let primary = async {
                loop {
                    let incoming = tokio::select! {
                        _ = &mut stopped => break,
                        incoming = listener.accept() => (incoming?, false),
                        incoming = async {
                            match &ipv6 {
                                Some(listener) => listener.accept().await,
                                None => std::future::pending().await,
                            }
                        } => (incoming?, true),
                        joined = workers.join_next(), if !workers.is_empty() => {
                            joined.ok_or("application worker disappeared")???;
                            continue;
                        }
                    };
                    let acceptor = acceptor.clone();
                    workers.spawn(async move {
                        let mut stream = match accept_tls_stream(incoming.0.0, acceptor).await {
                            Ok(stream) => stream,
                            Err(error) if dual_origin && cancelled_backup(error.as_ref()) => return Ok(()),
                            Err(error) => return Err(error),
                        };
                        let request = match read_head(&mut stream).await {
                            Ok(request) => request,
                            Err(error) if dual_origin && is_peer_gone(&error) => return Ok(()),
                            Err(error) => return Err(error.into()),
                        };
                        if !request.starts_with(b"GET / HTTP/1.1\r\n") { return Err("unexpected application request".into()); }
                        let body = if incoming.1 { "ipv6" } else { "ipv4" };
                        let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n{body}");
                        stream.write_all(reply.as_bytes()).await?;
                        stream.flush().await?;
                        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                    });
                }
                Ok(())
            }.await;
            workers.abort_all();
            let mut cleanup = Ok(());
            while let Some(joined) = workers.join_next().await {
                let result = match joined {
                    Ok(result) => result,
                    Err(error) if error.is_cancelled() => Ok(()),
                    Err(error) => Err(error.into()),
                };
                cleanup = finish_with_cleanup(cleanup, result);
            }
            finish_with_cleanup(primary, cleanup)
        });
        Ok(Self {
            client,
            doh,
            url: format!("https://application.test:{port}/"),
            origin,
            stop: Some(stop),
        })
    }

    pub(crate) async fn finish(&mut self, primary: TestResult<()>) -> TestResult<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let joined = match timeout(Duration::from_secs(5), self.origin.join()).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        };
        finish_with_cleanup(
            primary,
            finish_with_cleanup(joined, self.origin.shutdown().await),
        )
    }
}

pub(crate) async fn get(client: &Client, url: &str) -> TestResult<Bytes> {
    let response = client.get(HttpProtocol::Http1, url)?.send().await?;
    if response.status() != 200 {
        return Err("application status was not successful".into());
    }
    Ok(response.into_body().collect().await?.to_bytes())
}

pub(crate) async fn drive(
    peer: &mut Peer,
    application: &Application,
    expected_queries: usize,
    mut response: impl FnMut(&Question) -> TestResult<Reply>,
) -> TestResult<TestResult<Bytes>> {
    let operation = get(&application.client, &application.url);
    tokio::pin!(operation);
    let mut count = 0;
    let result = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                result = &mut operation => break result,
                request = peer.requests.recv() => {
                    let request = request.ok_or("DNS fixture closed before lookup completed")?;
                    count += 1;
                    if count > expected_queries { return Err("unexpected extra DNS exchange".into()); }
                    let reply = response(&request.question)?;
                    request.reply(reply)?;
                }
            }
        }
    }).await?;
    equal(count, expected_queries)?;
    Ok(result)
}

pub(crate) fn equal<T: PartialEq + std::fmt::Debug>(actual: T, expected: T) -> TestResult<()> {
    if actual != expected {
        return Err(format!("observed {actual:?}, expected {expected:?}").into());
    }
    Ok(())
}

pub(crate) struct Fixture {
    pub(crate) peer: Peer,
    pub(crate) application: Application,
}

impl Fixture {
    pub(crate) async fn start(
        families: DohAddressFamilies,
        lookup_timeout: Duration,
        cache: bool,
        dual_origin: bool,
    ) -> TestResult<Self> {
        let identity = TestIdentity::generate_for_dns("resolver.test")?;
        let mut peer = Peer::start(&identity).await?;
        match Application::start(
            &identity,
            peer.port,
            families,
            lookup_timeout,
            cache,
            dual_origin,
        )
        .await
        {
            Ok(application) => Ok(Self { peer, application }),
            Err(error) => {
                peer.finish(Err(error)).await?;
                Err("failed fixture setup did not retain initiating error".into())
            }
        }
    }

    pub(crate) async fn finish(&mut self, primary: TestResult<()>) -> TestResult<()> {
        let primary = self.application.finish(primary).await;
        self.peer.finish(primary).await
    }
}

// Only the dual-loopback row can accept a losing connection before the
// client cancels its address race. Certificate and protocol failures still
// reach owned cleanup.
fn cancelled_backup(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(is_peer_gone)
            || error
                .downcast_ref::<btls::ssl::Error>()
                .is_some_and(|error| error.io_error().is_some_and(is_peer_gone))
        {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}
