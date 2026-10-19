use std::{net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use phantom::{
    Client, HttpProtocol,
    dns::{DnsOverHttps, DohAddressFamilies, DohConfiguration, DohMethod},
    profile::{ClientProfile, browser::chrome},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use crate::support::{
    tls::{H1_ALPN, TestIdentity, TestResult, accept_tls, read_head, tls_settings},
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

mod answers;
mod failures;
mod lifecycle;
mod over_tls;
mod peer;

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::test]
async fn get_bootstraps_verified_dns_identity_and_keeps_query_parameters() -> TestResult<()> {
    exchange(DohMethod::Get, false, false, 206).await
}

#[tokio::test]
async fn post_keeps_navigation_fields_and_client_hint_restarts_out_of_dns() -> TestResult<()> {
    exchange(DohMethod::Post, true, false, 200).await
}

#[tokio::test]
async fn ip_literal_bootstrap_keeps_the_verified_ip_authority() -> TestResult<()> {
    exchange(DohMethod::Post, false, true, 200).await
}

async fn exchange(
    method: DohMethod,
    chromium: bool,
    ip_endpoint: bool,
    status: u16,
) -> TestResult<()> {
    let resolver_identity = if ip_endpoint {
        TestIdentity::generate()?
    } else {
        TestIdentity::generate_for_dns("resolver.test")?
    };
    let origin_identity = TestIdentity::generate_for_dns("answer.test")?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_port = listener.local_addr()?.port();
    let acceptor = origin_identity.acceptor(H1_ALPN)?;
    let mut dns = peer::start(&resolver_identity, status).await?;
    let mut origin = ConnectionPeer::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        let head = read_head(&mut stream).await?;
        assert!(head.starts_with(b"GET /application HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
        stream.flush().await?;
        Ok(())
    });
    let primary = timeout(DEADLINE, async {
        let host = if ip_endpoint {
            "127.0.0.1"
        } else {
            "resolver.test"
        };
        let endpoint = format!("https://{host}:{}/dns-query?fixture=retained", dns.port);
        let mut configuration = DohConfiguration::new(
            endpoint,
            [Ipv4Addr::LOCALHOST.into()],
            method,
            DohAddressFamilies::Ipv4Only,
            DEADLINE,
            NonZeroUsize::new(2).ok_or("zero admission")?,
        );
        if chromium {
            configuration = configuration.chromium154_wire();
        }
        // This profile includes ordinary navigation fields and client hints.
        // The DNS client must apply only its transport layers.
        let profile = ClientProfile::new(tls_settings())
            .with_http2(chrome::v154_http2())
            .with_client_hints(chrome::v154_windows_client_hints())
            .with_request_template(chrome::v154_windows_navigation_template());
        let doh = DnsOverHttps::builder(profile, configuration)?
            .add_root_certificate_der(resolver_identity.root_der.clone())
            .build()?;
        let mut application_tls = tls_settings();
        application_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
        let application = Client::builder(ClientProfile::new(application_tls))
            .add_root_certificate_der(origin_identity.root_der.clone())
            .dns_resolver(doh.address_resolver())
            .no_dns_cache()
            .build()?;
        let application_url = format!("https://answer.test:{origin_port}/application");
        let response = application
            .get(HttpProtocol::Http1, &application_url)?
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        let observed = dns.queries.recv().await.ok_or("missing DNS observation")?;
        assert_eq!(
            observed.method,
            match method {
                DohMethod::Get => http::Method::GET,
                DohMethod::Post => http::Method::POST,
            }
        );
        assert_eq!(
            observed
                .uri
                .authority()
                .ok_or("missing authority")?
                .as_str(),
            format!("{host}:{}", dns.port)
        );
        assert!(
            observed
                .uri
                .query()
                .ok_or("missing retained parameter")?
                .contains("fixture=retained")
        );
        assert_eq!(observed.headers["accept"], "application/dns-message");
        assert_eq!(observed.headers["accept-encoding"], "identity");
        for name in [
            "cookie",
            "authorization",
            "sec-ch-ua",
            "sec-ch-ua-platform",
            "sec-fetch-site",
        ] {
            assert!(
                !observed.headers.contains_key(name),
                "unexpected DNS field {name}"
            );
        }
        assert_eq!(&observed.bytes[..2], &[0, 0]);
        assert_eq!(
            &observed.bytes[12..29],
            b"\x06answer\x04test\x00\x00\x01\x00\x01"
        );
        if chromium {
            assert_eq!(observed.headers["user-agent"], "Chrome");
            assert_eq!(observed.headers["accept-language"], "*");
            assert_chromium_padding(&observed.bytes)?;
        } else {
            assert!(!observed.headers.contains_key("user-agent"));
        }
        if method == DohMethod::Post {
            assert_eq!(observed.headers["content-type"], "application/dns-message");
        }
        assert!(matches!(
            dns.queries.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        drop(application);
        drop(doh);
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
    .and_then(|result| result);
    let primary = finish_with_cleanup(primary, origin.shutdown().await);
    finish_with_cleanup(primary, dns.finish().await)
}

fn assert_chromium_padding(query: &[u8]) -> TestResult<()> {
    assert_eq!(&query[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
    // Root-name OPT, type 41, UDP size 4096, EDNS version/flags zero.
    assert_eq!(query.get(29..38), Some(&[0, 0, 41, 16, 0, 0, 0, 0, 0][..]));
    let rdlength = query.get(38..40).ok_or("missing OPT RDLENGTH")?;
    let rdlength = usize::from(u16::from_be_bytes([rdlength[0], rdlength[1]]));
    assert_eq!(rdlength + 40, query.len());
    assert_eq!(query.get(40..42), Some(&[0, 12][..]));
    let length = query.get(42..44).ok_or("missing EDNS padding length")?;
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    assert_eq!(rdlength, 4 + length);
    assert_eq!(query.len(), 128);
    assert_eq!(length, 84);
    assert!(query[44..].iter().all(|byte| *byte == 0));
    Ok(())
}
