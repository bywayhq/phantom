//! Negotiated Firefox requests reuse an authenticated HTTP/3 donor across origins.

use std::{net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use phantom::{
    AltSvcPolicy, Client, HttpProtocol, RequestHeader, ResponseInfo, profile::browser::firefox,
};
use tokio::{sync::watch, time::timeout};

use crate::support::{
    tls::{TestIdentity, TestResult},
    tunnel_proxy::finish_with_cleanup,
};

use self::peer::{Observation, Peer};

mod peer;

const DONOR: &str = "donor.test";
const OTHER: &str = "other.test";
const DEADLINE: Duration = Duration::from_secs(10);
const CLEANUP: Duration = Duration::from_secs(5);
const FIELDS: [(&str, &str); 2] = [("x-first", "one"), ("x-last", "two")];

#[derive(Clone, Copy)]
enum CertificateScope {
    BothOrigins,
    DonorOnly,
}

#[tokio::test]
async fn firefox_reuses_settled_h3_for_an_authorized_origin_without_its_alt_svc() -> TestResult<()>
{
    let exchange = exchange(CertificateScope::BothOrigins).await?;

    assert_eq!(
        exchange.protocols,
        [
            HttpProtocol::Http1,
            HttpProtocol::Http3,
            HttpProtocol::Http3
        ],
        "TCP requests: {:?}; HTTP/3 requests: {:?}",
        exchange.tcp,
        exchange.h3
    );
    assert_eq!(exchange.tcp.len(), 1);
    let donor = find(&exchange.h3, DONOR, "/settled")?;
    let other = find(&exchange.h3, OTHER, "/first")?;

    assert_eq!(other.connection, donor.connection);
    assert_ne!(other.stream, donor.stream);
    assert_other_fields(other);
    Ok(())
}

#[tokio::test]
async fn firefox_does_not_reuse_a_settled_h3_donor_whose_certificate_excludes_the_origin()
-> TestResult<()> {
    let exchange = exchange(CertificateScope::DonorOnly).await?;

    assert_eq!(
        exchange.protocols,
        [
            HttpProtocol::Http1,
            HttpProtocol::Http3,
            HttpProtocol::Http1
        ],
        "TCP requests: {:?}; HTTP/3 requests: {:?}",
        exchange.tcp,
        exchange.h3
    );
    find(&exchange.h3, DONOR, "/settled")?;
    assert_eq!(exchange.h3.len(), 1);
    let other = find(&exchange.tcp, OTHER, "/first")?;
    assert_other_fields(other);
    Ok(())
}

fn find<'a>(records: &'a [Observation], host: &str, path: &str) -> TestResult<&'a Observation> {
    records
        .iter()
        .find(|record| record.authority.starts_with(&format!("{host}:")) && record.path == path)
        .ok_or_else(|| format!("missing {host}{path} in peer records: {records:?}").into())
}

fn assert_other_fields(record: &Observation) {
    assert_eq!(record.method, "GET");
    let fields: Vec<_> = record
        .fields
        .iter()
        .filter(|(name, _)| name.starts_with("x-"))
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect();
    assert_eq!(
        fields,
        [
            ("x-first", b"one".as_slice()),
            ("x-last", b"two".as_slice())
        ]
    );
    assert!(record.fields.iter().all(|(name, _)| name != "alt-used"));
}

struct Exchange {
    protocols: [HttpProtocol; 3],
    tcp: Vec<Observation>,
    h3: Vec<Observation>,
}

async fn exchange(scope: CertificateScope) -> TestResult<Exchange> {
    let tcp_identity = TestIdentity::generate_for_dns_names(&[DONOR, OTHER])?;
    let quic_names: &[&str] = match scope {
        CertificateScope::BothOrigins => &[DONOR, OTHER],
        CertificateScope::DonorOnly => &[DONOR],
    };
    let quic_identity = TestIdentity::generate_for_dns_names(quic_names)?;
    let peer = Peer::bind(&tcp_identity, &quic_identity).await?;
    let client = Client::builder(firefox::v157_windows())
        .add_root_certificate_der(tcp_identity.root_der.clone())
        .add_root_certificate_der(quic_identity.root_der.clone())
        .resolve(DONOR, [Ipv4Addr::LOCALHOST.into()])
        .resolve(OTHER, [Ipv4Addr::LOCALHOST.into()])
        .alt_svc(NonZeroUsize::new(8).ok_or("invalid Alt-Svc fixture capacity")?)
        .alt_svc_policy(AltSvcPolicy::sequential())
        .build()?;
    let (stop, stopped) = watch::channel(false);
    let request = async {
        let mut protocols = Vec::new();
        for (host, path) in [(DONOR, "/learn"), (DONOR, "/settled"), (OTHER, "/first")] {
            let url = format!("https://{host}:{}{path}", peer.address.port());
            let mut request = client.get_negotiated(&url)?;
            for (name, value) in FIELDS {
                request = request.header(RequestHeader::new(name, value));
            }
            let response = request.send().await?;
            let protocol = response
                .extensions()
                .get::<ResponseInfo>()
                .ok_or("response omitted its selected protocol")?
                .protocol();
            let body = response.into_body().collect_with_limit(2).await?;
            if body != b"ok"[..] {
                return Err("coalescing response body differs from the peer payload".into());
            }
            if host == DONOR && path == "/settled" && protocol != HttpProtocol::Http3 {
                return Err("donor did not settle on HTTP/3 before the second origin".into());
            }
            // In particular, A's HTTP/3 body is complete before B is initiated.
            protocols.push(protocol);
        }
        stop.send(true)
            .map_err(|_| "coalescing peers stopped early")?;
        let protocols = protocols
            .try_into()
            .map_err(|_| "missing coalescing response")?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(protocols)
    };
    // Dropping this joined operation cancels all peer futures; none is detached.
    let result = match timeout(DEADLINE, async {
        tokio::try_join!(
            request,
            peer.serve_tcp(stopped.clone()),
            peer.serve_h3(stopped)
        )
    })
    .await
    {
        Ok(result) => result.map(|(protocols, tcp, h3)| Exchange { protocols, tcp, h3 }),
        Err(error) => Err(error.into()),
    };
    drop(client);
    peer.endpoint
        .close(0_u32.into(), b"coalescing fixture complete");
    let cleanup = async {
        timeout(CLEANUP, peer.endpoint.wait_idle()).await?;
        Ok(())
    }
    .await;
    finish_with_cleanup(result, cleanup)
}
