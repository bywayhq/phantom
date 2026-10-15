//! New dedicated CONNECT keeps its TCP early-data startup and error contract.

use crate::support::{
    h2::{accept_client_preface, read_request_headers, write_frame},
    tls::{H1_ALPN, H2_ALPN, TestIdentity, TestResult},
};
use btls::ssl::{AlpnError, ExtensionType, SelectCertError, SslAcceptor, select_next_proto};
use bytes::Bytes;
use http::{Method, Response};
use http_body_util::BodyExt as _;
use phantom::{
    Client, HttpProtocol, WebSocketErrorKind,
    profile::{ClientProfile, browser::firefox},
};
use std::{
    net::Ipv4Addr,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{io::AsyncWriteExt as _, net::TcpListener, time::timeout};

mod peer;
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Accepted,
    Rejected,
    AlpnChanged,
}

fn acceptor(
    identity: &TestIdentity,
    outcome: Outcome,
    offers: Arc<Mutex<Vec<bool>>>,
) -> TestResult<SslAcceptor> {
    let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
    acceptor.set_select_certificate_callback(move |hello| {
        offers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(hello.get_extension(ExtensionType::EARLY_DATA).is_some());
        Ok::<_, SelectCertError>(())
    });
    let index = AtomicUsize::new(0);
    acceptor.set_alpn_select_callback(move |_, offered| {
        let subsequent = index.fetch_add(1, Ordering::SeqCst) != 0;
        let selected = if subsequent && outcome == Outcome::AlpnChanged {
            H1_ALPN
        } else {
            H2_ALPN
        };
        select_next_proto(selected, offered).ok_or(AlpnError::NOACK)
    });
    Ok(acceptor.build())
}

async fn control(negotiated: bool, outcome: Outcome) -> TestResult<()> {
    timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let offers = Arc::new(Mutex::new(Vec::new()));
        let acceptor = acceptor(&identity, outcome, Arc::clone(&offers))?;
        let profile = ClientProfile::new(firefox::v157_tcp_tls())
            .with_http1(firefox::v157_http1())
            .with_http2(firefox::v157_http2())
            .with_websocket(firefox::v157_websocket());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let caller = async {
            let seed = format!("https://{address}/seed");
            let request = if negotiated {
                client.get_negotiated(&seed)?
            } else {
                client.get(HttpProtocol::Http2, &seed)?
            };
            let response = request.send().await?;
            assert_eq!(response.status(), 200);
            response.into_body().collect().await?;
            let url = format!("wss://{address}/events");
            let request = if negotiated {
                client.websocket_with_profile_policy(&url)?
            } else {
                client.websocket_with_protocol(HttpProtocol::Http2, &url)?
            };
            let result = request.connect().await;
            if outcome == Outcome::AlpnChanged {
                let error = match result {
                    Ok(_) => return Err("changed ALPN opened a WebSocket".into()),
                    Err(error) => error,
                };
                assert_eq!(error.kind(), WebSocketErrorKind::Http2);
                assert!(
                    peer::source_chain(&error).contains("unsupported by the HTTP/2 transport"),
                    "lost the original TLS ALPN error: {error}"
                );
            } else {
                let socket = result?;
                assert_eq!(socket.handshake_response().status(), 200);
                drop(socket);
            }
            TestResult::Ok(())
        };
        let server = async {
            let mut seed = peer::accept(&listener, &acceptor, true, Duration::ZERO).await?;
            accept_client_preface(&mut seed).await?;
            read_request_headers(&mut seed, 3).await?;
            // GOAWAY precedes the response on the wire, so policy selection
            // cannot reuse the seed when response completion releases the caller.
            let mut goaway = [0; 8];
            goaway[..4].copy_from_slice(&3_u32.to_be_bytes());
            write_frame(&mut seed, 7, 0, 0, &goaway).await?;
            write_frame(&mut seed, 1, 5, 3, &[0x88]).await?;
            seed.flush().await?;
            let resumed = peer::accept(
                &listener,
                &acceptor,
                outcome == Outcome::Accepted,
                Duration::from_millis(200),
            )
            .await?;
            if outcome == Outcome::AlpnChanged {
                peer::no_application(resumed).await?;
            } else {
                assert_eq!(
                    resumed.stream.ssl().early_data_accepted(),
                    outcome == Outcome::Accepted
                );
                assert!(
                    resumed.stream.ssl().session_reused(),
                    "test did not resume an actual ticket"
                );
                let early = resumed.early_bytes();
                let mut builder = ::http2::server::Builder::new();
                builder.enable_connect_protocol();
                let mut connection = builder.handshake::<_, Bytes>(resumed).await?;
                let (request, mut respond) = connection
                    .accept()
                    .await
                    .ok_or("missing resumed CONNECT")??;
                assert_eq!(request.method(), Method::CONNECT);
                assert_eq!(request.uri().path(), "/events");
                let early = early.lock().unwrap_or_else(PoisonError::into_inner).clone();
                if outcome == Outcome::Accepted {
                    assert!(
                        peer::frame_types(&early)?.contains(&4),
                        "accepted early data omitted SETTINGS"
                    );
                    assert!(
                        !peer::frame_types(&early)?.contains(&1),
                        "CONNECT HEADERS were sent as early data"
                    );
                } else {
                    assert!(
                        early.is_empty(),
                        "rejected early data reached the server application"
                    );
                }
                respond.send_response(Response::new(()), false)?;
                // Drive the response and observe cancellation. A second stream
                // would be an opening replay and is not accepted as cleanup.
                match connection.accept().await {
                    Some(Ok(_)) => return Err("resumed opening replayed CONNECT".into()),
                    Some(Err(error))
                        if error
                            .get_io()
                            .is_some_and(crate::support::tls::is_peer_gone) => {}
                    Some(Err(error)) => return Err(error.into()),
                    None => {}
                }
            }
            assert_eq!(
                *offers.lock().unwrap_or_else(PoisonError::into_inner),
                [false, true]
            );
            assert!(
                timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "opening error created another connection"
            );
            drop(seed);
            TestResult::Ok(())
        };
        tokio::try_join!(caller, server)?;
        Ok(())
    })
    .await
    .map_err(|_| "H2 WebSocket early-data control exceeded its deadline")?
}

#[tokio::test]
async fn accepted_tcp_early_data_contains_startup_but_no_connect() -> TestResult<()> {
    for negotiated in [false, true] {
        control(negotiated, Outcome::Accepted).await?;
    }
    Ok(())
}

#[tokio::test]
async fn rejected_tcp_early_data_replays_startup_once_before_connect() -> TestResult<()> {
    for negotiated in [false, true] {
        control(negotiated, Outcome::Rejected).await?;
    }
    Ok(())
}

#[tokio::test]
async fn changed_alpn_after_early_data_returns_the_setup_error_without_fallback() -> TestResult<()>
{
    for negotiated in [false, true] {
        control(negotiated, Outcome::AlpnChanged).await?;
    }
    Ok(())
}
