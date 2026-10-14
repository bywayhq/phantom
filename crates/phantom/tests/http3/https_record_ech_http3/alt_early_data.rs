//! Native alternate-host ECH with real gated HTTP/3 early requests.

use std::{collections::VecDeque, net::SocketAddr};

use bytes::Buf;
use phantom::AltSvcHttpsPolicy;
use phantom_net::dns::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup};
use tokio::sync::mpsc;
use tracing::instrument::WithSubscriber;

use crate::support::tracing::OutcomeSubscriber;

use super::*;

mod cases;
mod gate;
mod peer;

const DESTINATION: &str = "early-alternative.test";
const QUIET_WINDOW: Duration = Duration::from_millis(300);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Attempt {
    Accept,
    RejectEarly,
    Post,
    GetBody,
    GetTrailers,
    RejectEch,
    Cancel,
}

#[derive(Debug)]
struct RequestSeen {
    connection: usize,
    stable_id: usize,
    method: http::Method,
    authority: String,
    path: String,
    marker: String,
    body: Vec<u8>,
    trailer: Option<String>,
    gate_open: bool,
}

#[derive(Debug)]
struct PendingSeen {
    connection: usize,
    stable_id: usize,
    outer_name: Option<String>,
    offered_early: bool,
    native: ServerHandshakeData,
}

#[derive(Debug)]
enum Event {
    Pending(PendingSeen),
    Request(RequestSeen),
    Complete {
        connection: usize,
        stable_id: usize,
        server_notification: bool,
        native: ServerHandshakeData,
    },
    Drained,
    EchFailed(u64),
    Finished,
}

fn destination_client(
    identity: &TestIdentity,
    queries: Arc<std::sync::Mutex<Vec<(String, u16)>>>,
) -> TestResult<Client> {
    let ech = ech_config_list(&[ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME)]);
    let record = HttpsRecord::from_rdata(&https_rdata_with_alpn(&[b"h3"], &ech))?;
    let resolver = HttpsRecordResolver::from_fn(move |host, port| {
        let record = record.clone();
        let queries = queries.clone();
        async move {
            queries
                .lock()
                .map_err(|_| {
                    phantom_net::dns::HttpsLookupError::other(std::io::Error::other(
                        "query observer poisoned",
                    ))
                })?
                .push((host.to_owned(), port));
            Ok(if host == DESTINATION {
                HttpsRecordLookup::new(vec![HttpsRecordAnswer::new(DESTINATION, 300, record)], None)
            } else {
                HttpsRecordLookup::new(Vec::new(), Some(300))
            })
        }
    });
    Ok(Client::builder(profile(true))
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN.saturating_add(7))
        .alt_svc_policy(AltSvcPolicy::sequential())
        .alt_svc_https_policy(AltSvcHttpsPolicy::Destination {
            lookup_timeout: Duration::from_secs(1),
        })
        .https_record_discovery(resolver)
        .http3_early_data(true)
        .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
        .resolve(DESTINATION, [Ipv4Addr::LOCALHOST.into()])
        .build()?)
}

async fn send(client: Client, url: String, attempt: Attempt) -> TestResult<()> {
    let method = if attempt == Attempt::Post {
        http::Method::POST
    } else {
        http::Method::GET
    };
    let mut request = client
        .request_negotiated(method, &url)?
        .header(phantom::RequestHeader::new("x-early-marker", "unchanged"));
    if matches!(attempt, Attempt::Post | Attempt::GetBody) {
        request = request.body(Bytes::from_static(b"request-body"));
    }
    if attempt == Attempt::GetTrailers {
        request = request.trailers(vec![phantom::RequestHeader::new("x-early-trailer", "end")]);
    }
    let response = request.send().await.inspect_err(|error| {
        let mut source: Option<&dyn Error> = Some(error);
        for depth in 0..16 {
            let Some(error) = source else { break };
            eprintln!("native request cause[{depth}]: {error:?}; {error}");
            source = error.source();
        }
    })?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .extensions()
            .get::<ResponseInfo>()
            .map(ResponseInfo::protocol),
        Some(HttpProtocol::Http3)
    );
    assert_eq!(
        response.into_body().collect().await?.to_bytes(),
        Bytes::from_static(b"ok")
    );
    Ok(())
}

async fn early_dispatch(subscriber: &OutcomeSubscriber) {
    while subscriber.early_data_for("http3.response_head").is_empty() {
        tokio::task::yield_now().await;
    }
}

async fn next(events: &mut mpsc::UnboundedReceiver<Event>) -> TestResult<Event> {
    let event = timeout(TEST_TIMEOUT, events.recv())
        .await?
        .ok_or("native peer ended before observation")?;
    eprintln!("native early-data observation: {event:?}");
    Ok(event)
}
