use std::{net::SocketAddr, time::Duration};

use phantom_profile::browser::{chrome, firefox};
use phantom_testkit::tls::{TEST_ECH_KEYS, ech_config, ech_config_list};
use tokio::{sync::oneshot, task::JoinSet};

use super::*;
use crate::{
    direct::{EchEarlyData, SelectedEch},
    dns::EchConfigList,
    host_resolver::HostResolver,
    http1_or_2::{Http1Or2Connection, Http1Or2TlsConnector},
    http2::Http2Connection,
    tcp::SlowerAttempt,
};

mod peer;

const INNER_NAME: &str = "inner.phantom.test";
const PUBLIC_NAME: &str = "public.phantom.test";

#[derive(Clone, Copy)]
enum Connector {
    ExactH2,
    NegotiatedH2,
}

#[derive(Clone, Copy)]
enum Peer {
    Accepted,
    AuthenticatedRetry,
}

async fn retained(
    connector: Connector,
    identity: &TestIdentity,
    address: SocketAddr,
) -> TestResult<Http2Connection> {
    let mut settings = firefox::v157_tcp_tls();
    settings.ech = chrome::v154_tcp_tls().ech;
    let selected = SelectedEch::new(
        Some(EchConfigList::new(ech_config_list(&[ech_config(
            1,
            &TEST_ECH_KEYS[0],
            PUBLIC_NAME,
        )]))),
        EchEarlyData::Allowed,
    )
    .map_err(|_| "valid retained ECH configuration rejected")?;
    // The TCP race already selected `address`. An ECH retry must use that
    // endpoint, not resolve the now-different address below.
    let resolver = HostResolver::new().with_override(
        INNER_NAME,
        vec![std::net::Ipv4Addr::new(127, 0, 0, 2).into()],
    );
    let attempt = SlowerAttempt::scripted(TcpStream::connect(address), Duration::ZERO, None);
    let connection = match connector {
        Connector::ExactH2 => Http2TlsConnector::new_with_additional_roots(
            &settings,
            &firefox::v157_http2(),
            [identity.root_der()],
        )?
        .with_tcp_settings(&firefox::v157_tcp())
        .with_host_resolver(resolver)
        .slower_connection(attempt, INNER_NAME, Some(selected))
        .finish()
        .await
        .ok_or("retained exact-H2 ECH setup failed")?,
        Connector::NegotiatedH2 => {
            let connection = Http1Or2TlsConnector::new_with_additional_roots(
                &settings,
                &firefox::v157_http2(),
                [identity.root_der()],
            )?
            .with_tcp_settings(&firefox::v157_tcp())
            .with_host_resolver(resolver)
            .slower_connection_with_ech(attempt, INNER_NAME, selected)
            .finish()
            .await
            .ok_or("retained negotiated-H2 ECH setup failed")?;
            let Http1Or2Connection::Http2(connection) = connection else {
                return Err("retained ECH setup negotiated HTTP/1.1 instead of HTTP/2".into());
            };
            connection
        }
    };
    assert_eq!(connection.origin_ech_configured(), Some(true));
    Ok(connection)
}

async fn requests(connector: Connector, behavior: Peer) -> TestResult<()> {
    let identity = TestIdentity::generate_for_names(&[INNER_NAME, PUBLIC_NAME])?;
    let acceptor = peer::acceptor(&identity, behavior)?;
    let (address, listener) = loopback_listener().await?;
    let mut tasks = JoinSet::new();
    tasks.spawn(peer::requests(listener, acceptor, behavior));
    tasks.spawn(async move {
        let connection = retained(connector, &identity, address).await?;
        for path in ["/first", "/second"] {
            let response = connection
                .send_get(INNER_NAME, OriginForm::parse(path)?, vec![])
                .await?;
            assert_eq!(response.status(), 204);
            assert!(response.into_body().collect().await?.to_bytes().is_empty());
        }
        drop(connection);
        Ok(())
    });
    finish(tasks).await
}

async fn cancellation(connector: Connector) -> TestResult<()> {
    let identity = TestIdentity::generate_for_names(&[INNER_NAME, PUBLIC_NAME])?;
    let (address, listener) = loopback_listener().await?;
    let (seen, entered) = oneshot::channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(peer::cancelled(listener, seen));
    tasks.spawn(async move {
        {
            let opening = retained(connector, &identity, address);
            tokio::pin!(opening);
            tokio::select! {
                result = &mut opening => {
                    result?;
                    return Err("retained TLS completed before the peer answered".into());
                }
                result = entered => result?,
            }
        }
        // Drop the actual in-flight handshake after the peer saw its ECH
        // ClientHello. The peer must observe closure, without an HTTP request.
        Ok(())
    });
    finish(tasks).await
}

async fn finish(mut tasks: JoinSet<TestResult<()>>) -> TestResult<()> {
    let primary = timeout(TEST_TIMEOUT, async {
        while let Some(result) = tasks.join_next().await {
            result??;
        }
        TestResult::<()>::Ok(())
    })
    .await;
    tasks.abort_all();
    let mut failures = Vec::new();
    match primary {
        Ok(Ok(())) => {}
        Ok(Err(error)) => failures.push(error.to_string()),
        Err(error) => failures.push(format!("retained ECH test exceeded its deadline: {error}")),
    }
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(format!("peer cleanup: {error}")),
            Err(error) if error.is_cancelled() => {}
            Err(error) => failures.push(format!("peer cleanup: {error}")),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

#[tokio::test]
async fn exact_h2_retained_ech_authenticates_and_reuses_one_session() -> TestResult<()> {
    requests(Connector::ExactH2, Peer::Accepted).await
}

#[tokio::test]
async fn negotiated_h2_retained_ech_authenticates_and_reuses_one_session() -> TestResult<()> {
    requests(Connector::NegotiatedH2, Peer::Accepted).await
}

#[tokio::test]
async fn exact_h2_retained_ech_retries_on_fresh_tcp_at_the_selected_endpoint() -> TestResult<()> {
    requests(Connector::ExactH2, Peer::AuthenticatedRetry).await
}

#[tokio::test]
async fn negotiated_h2_retained_ech_retries_on_fresh_tcp_at_the_selected_endpoint() -> TestResult<()>
{
    requests(Connector::NegotiatedH2, Peer::AuthenticatedRetry).await
}

#[tokio::test]
async fn cancelling_exact_h2_retained_ech_closes_its_handshake_socket() -> TestResult<()> {
    cancellation(Connector::ExactH2).await
}

#[tokio::test]
async fn cancelling_negotiated_h2_retained_ech_closes_its_handshake_socket() -> TestResult<()> {
    cancellation(Connector::NegotiatedH2).await
}
