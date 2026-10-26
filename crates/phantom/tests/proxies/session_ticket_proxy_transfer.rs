//! Origin TLS ticket transfer through an authenticated HTTP CONNECT proxy.

use std::{net::Ipv4Addr, pin::Pin, sync::Arc, time::Duration};

use btls::ssl::{Ssl, SslAcceptor, SslVersion};
use phantom::{
    Client, HttpProtocol, HttpProxy, Route, SessionTicketErrorKind,
    profile::{
        CipherSuite, ClientProfile, NamedGroup, TlsVersion, TlsVersionRange, browser::chrome,
    },
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};
use tokio_btls::SslStream;

use crate::support::{
    tls::{self, H1_ALPN, TestIdentity, TestResult},
    tunnel_proxy::{
        finish_with_cleanup, http1_challenge_then_connect_on, http1_connect_on,
        https1_challenge_then_connect_on, setup::TunnelSetup,
    },
};

const KEY: [u8; 32] = [7; 32];
const DEADLINE: Duration = Duration::from_secs(15);

struct Fixture {
    identity: TestIdentity,
    profile: ClientProfile,
    version: SslVersion,
    proxy: Arc<TcpListener>,
    origins: [TcpListener; 2],
    proxy_tls: Option<SslAcceptor>,
}

impl Fixture {
    async fn new(version: TlsVersion) -> TestResult<Self> {
        let mut settings = tls::tls_settings();
        settings.versions = TlsVersionRange::only(version);
        settings.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
        if version == TlsVersion::Tls13 {
            settings.cipher_suites = vec![CipherSuite::Aes128GcmSha256];
            settings.groups = vec![NamedGroup::X25519];
            settings.key_shares = vec![NamedGroup::X25519];
        }
        let version = match version {
            TlsVersion::Tls12 => SslVersion::TLS1_2,
            TlsVersion::Tls13 => SslVersion::TLS1_3,
            _ => return Err("fixture supports TLS 1.2 and TLS 1.3 only".into()),
        };
        Ok(Self {
            identity: TestIdentity::generate()?,
            proxy_tls: None,
            profile: ClientProfile::new(settings),
            version,
            proxy: Arc::new(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?),
            origins: [
                TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?,
                TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?,
            ],
        })
    }

    async fn negotiated_https(version: TlsVersion) -> TestResult<Self> {
        let mut fixture = Self::new(version).await?;
        let mut settings = fixture.profile.tls().clone();
        settings.alpn_protocols = vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])];
        fixture.profile = ClientProfile::new(settings).with_http2(chrome::v154_http2());
        fixture.proxy_tls = Some(fixture.server()?);
        Ok(fixture)
    }

    fn client(&self, route: Route) -> TestResult<Client> {
        let mut builder = Client::builder(self.profile.clone())
            .add_root_certificate_der(self.identity.root_der.clone())
            .route(route);
        if self.proxy_tls.is_some() {
            builder = builder
                .add_proxy_root_certificate_der(self.identity.root_der.clone())
                .preemptive_proxy_authentication(false);
        }
        Ok(builder.build()?)
    }

    fn route(&self, password: &str) -> TestResult<Route> {
        Ok(Route::http_proxy(
            HttpProxy::new(&format!(
                "{}://{}",
                if self.proxy_tls.is_some() {
                    "https"
                } else {
                    "http"
                },
                self.proxy.local_addr()?
            ))?
            .with_basic_auth("u", password)?,
        ))
    }

    fn server(&self) -> TestResult<SslAcceptor> {
        let mut builder = self.identity.acceptor_builder(H1_ALPN)?;
        builder.set_min_proto_version(Some(self.version))?;
        builder.set_max_proto_version(Some(self.version))?;
        Ok(builder.build())
    }

    async fn exchange(
        &self,
        client: &Client,
        origin: usize,
        server: &SslAcceptor,
        resumed: bool,
        challenge: bool,
    ) -> TestResult<()> {
        let listener = &self.origins[origin];
        let address = listener.local_addr()?;
        let proxy = self.proxy.clone();
        let route = self.route("p")?;
        let proxy_tls = self.proxy_tls.clone();
        let mut setup = TunnelSetup::spawn(async move {
            if let Some(acceptor) = proxy_tls {
                Ok(https1_challenge_then_connect_on(&proxy, acceptor, address)
                    .await?
                    .map(|(anonymous, authorized, _)| (Some(anonymous), authorized)))
            } else if challenge {
                Ok(http1_challenge_then_connect_on(&proxy, address)
                    .await?
                    .map(|(anonymous, authorized, _)| (Some(anonymous), authorized)))
            } else {
                Ok(http1_connect_on(&proxy, address)
                    .await?
                    .map(|authorized| (None, authorized)))
            }
        });

        // Keep the relay owner outside the request deadline so every exit joins it.
        let primary: TestResult<_> = match timeout(DEADLINE, async {
            tokio::try_join!(
                async {
                    let url = format!("https://{address}/");
                    let request = if self.proxy_tls.is_some() {
                        client.get(&url)?
                    } else {
                        client.get_with_protocol(HttpProtocol::Http1, &url)?
                    };
                    let response = request.route(route).send().await?;
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                        phantom::response_bytes(response, 1).await?,
                    )
                },
                async {
                    let (tcp, _) = listener.accept().await?;
                    let mut peer = SslStream::new(Ssl::new(server.context())?, tcp)?;
                    Pin::new(&mut peer).accept().await?;
                    let observed = (
                        peer.ssl().session_reused(),
                        peer.ssl().version2(),
                        peer.ssl().selected_alpn_protocol() == Some(&b"http/1.1"[..]),
                    );
                    let head = tls::read_head(&mut peer).await?;
                    peer.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
                    )
                    .await?;
                    peer.flush().await?;
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>((observed, head))
                },
                async {
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                        setup.establish().await?.clone(),
                    )
                }
            )
        })
        .await
        {
            Ok(result) => result,
            Err(elapsed) => Err(elapsed.into()),
        };
        let cleanup = setup.finish(Ok(())).await;
        let (response, ((actual_resumed, version, h1), origin_head), (anonymous, authorized)) =
            finish_with_cleanup(primary, cleanup)?;

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.body().as_ref(), b"x");
        assert_eq!(actual_resumed, resumed);
        assert_eq!(version, Some(self.version));
        assert!(h1);
        assert!(origin_head.starts_with(b"GET / HTTP/1.1\r\n"));
        assert!(!has_proxy_credentials(&origin_head));
        if let Some(anonymous) = anonymous {
            assert!(!has_proxy_credentials(&anonymous));
        }
        assert!(authorized.starts_with(format!("CONNECT {address} HTTP/1.1\r\n").as_bytes()));
        // Compare a boolean so failed assertions cannot print credentials.
        assert!(authorized.split(|byte| *byte == b'\n').any(|line| {
            let mut parts = line.splitn(2, |byte| *byte == b':');
            parts
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(b"proxy-authorization"))
                && parts.next() == Some(&b" Basic dTpw\r"[..])
        }));
        Ok(())
    }
}

fn has_proxy_credentials(head: &[u8]) -> bool {
    head.split(|byte| *byte == b'\n').any(|line| {
        line.split(|byte| *byte == b':')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(b"proxy-authorization"))
    })
}

#[tokio::test]
async fn credentialed_connect_import_resumes_the_first_cold_request_without_consuming_source()
-> TestResult<()> {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let fixture = Fixture::new(version).await?;
        let server = fixture.server()?;
        let source = fixture.client(Route::Direct)?;
        fixture.exchange(&source, 0, &server, false, true).await?;
        let snapshot = source.export_session_tickets(&KEY)?;
        fixture.exchange(&source, 0, &server, true, false).await?;

        let wrong = fixture.route("other")?;
        let correct = fixture.route("p")?;
        let recipient = fixture.client(wrong.clone())?;
        // A selected route and an earlier explicit route have the wrong credential.
        // The later compatible route authorizes import without rerouting requests.
        recipient.import_session_tickets(&snapshot, &KEY, &[wrong, correct])?;
        fixture.exchange(&recipient, 0, &server, true, true).await?;
    }
    Ok(())
}

#[tokio::test]
async fn credentialed_connect_import_replaces_a_warm_origin_ticket() -> TestResult<()> {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let fixture = Fixture::new(version).await?;
        let server = fixture.server()?;
        let old_server = fixture.server()?;
        let route = fixture.route("p")?;
        let source = fixture.client(Route::Direct)?;
        fixture.exchange(&source, 0, &server, false, true).await?;
        let snapshot = source.export_session_tickets(&KEY)?;

        let recipient = fixture.client(Route::Direct)?;
        fixture
            .exchange(&recipient, 0, &old_server, false, true)
            .await?;
        let old_snapshot = recipient.export_session_tickets(&KEY)?;
        let control = fixture.client(Route::Direct)?;
        control.import_session_tickets(&old_snapshot, &KEY, std::slice::from_ref(&route))?;
        // Independent server contexts cannot resume each other's tickets.
        fixture.exchange(&control, 0, &server, false, true).await?;

        recipient.import_session_tickets(&snapshot, &KEY, &[route])?;
        fixture
            .exchange(&recipient, 0, &server, true, false)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn altered_proxy_credentials_preserve_live_and_pending_tickets_before_correct_retry()
-> TestResult<()> {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let fixture = Fixture::new(version).await?;
        let server = fixture.server()?;
        let old_server = fixture.server()?;
        let route = fixture.route("p")?;
        let source = fixture.client(Route::Direct)?;
        fixture.exchange(&source, 0, &server, false, true).await?;
        fixture.exchange(&source, 1, &server, false, false).await?;
        let combined = source.export_session_tickets(&KEY)?;

        let prior_cold = fixture.client(Route::Direct)?;
        fixture
            .exchange(&prior_cold, 1, &server, false, true)
            .await?;
        let prior_snapshot = prior_cold.export_session_tickets(&KEY)?;
        let recipient = fixture.client(Route::Direct)?;
        fixture
            .exchange(&recipient, 0, &old_server, false, true)
            .await?;
        recipient.import_session_tickets(&prior_snapshot, &KEY, std::slice::from_ref(&route))?;

        // The first owner matches a warm route. The final cold owner has only a
        // wrong-credential route, so rejection must preserve both prior owners.
        let error = recipient
            .import_session_tickets(&combined, &KEY, &[fixture.route("other")?])
            .err()
            .ok_or("accepted altered proxy credentials")?;
        assert_eq!(error.kind(), SessionTicketErrorKind::Policy);
        fixture
            .exchange(&recipient, 0, &old_server, true, false)
            .await?;
        fixture
            .exchange(&recipient, 1, &server, true, false)
            .await?;

        recipient.import_session_tickets(&combined, &KEY, &[route])?;
        fixture
            .exchange(&recipient, 0, &server, true, false)
            .await?;
        fixture
            .exchange(&recipient, 1, &server, true, false)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn negotiated_https_connect_import_resumes_the_first_cold_origin_request() -> TestResult<()> {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let fixture = Fixture::negotiated_https(version).await?;
        let server = fixture.server()?;
        let route = fixture.route("p")?;
        let source = fixture.client(Route::Direct)?;
        fixture.exchange(&source, 0, &server, false, false).await?;
        let snapshot = source.export_session_tickets(&KEY)?;
        fixture.exchange(&source, 0, &server, true, false).await?;

        let recipient = fixture.client(Route::Direct)?;
        recipient.import_session_tickets(&snapshot, &KEY, &[route])?;
        fixture
            .exchange(&recipient, 0, &server, true, false)
            .await?;
    }
    Ok(())
}
