use std::{error::Error, net::Ipv4Addr, sync::Arc};

use phantom_profile::browser::chrome;
use tokio::time::timeout;

use super::{TEST_TIMEOUT, TestResult, early_data, quic_server};
use crate::{
    ServerSpkiPins, TlsError, TlsErrorKind,
    http3::{EarlyRace, Http3Connector},
    tls::test_support::{TEST_SERVER_NAME, TestIdentity},
};

fn pin_error(error: &(dyn Error + 'static)) -> Option<TlsErrorKind> {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if let Some(error) = error.downcast_ref::<TlsError>() {
            return Some(error.kind());
        }
        cause = error.source();
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pin_rejection_after_early_data_is_typed_during_and_after_session_start() -> TestResult<()>
{
    for during_start in [false, true] {
        timeout(TEST_TIMEOUT, async {
            let first = TestIdentity::generate()?;
            let changed = TestIdentity::generate()?;
            let key = btls::pkey::PKey::private_key_from_pkcs8(first.private_key_der())?;
            let pins = ServerSpkiPins::new(vec![btls::sha::sha256(&key.public_key_to_der()?)])?;
            let mut http3 = chrome::v154_http3();
            http3.qpack_decoder_stream = phantom_profile::Http3QpackDecoderStream::Eager;
            http3.qpack_encoder_stream = phantom_profile::Http3QpackEncoderStream::Eager;
            let mut connector = Http3Connector::new_with_spki_pins(
                &chrome::v154_quic_tls(),
                &chrome::v154_quic(),
                &http3,
                &chrome::v154_http3_request(),
                [first.root_der(), changed.root_der()],
                &pins,
            )?
            .with_isolated_session_cache();
            if during_start {
                connector =
                    connector.with_test_early_race(EarlyRace::StartAfterHandshake, Arc::default());
            }
            let endpoint = quic_server(
                early_data::server_config(&first, true)?,
                (Ipv4Addr::LOCALHOST, 0).into(),
            )?;
            let address = endpoint.local_addr()?;
            let (learned, learning_complete) = tokio::sync::oneshot::channel();
            let peer = async {
                let incoming = endpoint.accept().await.ok_or("first endpoint closed")?;
                eprintln!("pinned QUIC ({during_start}): learning peer accepted");
                let connection = incoming.await?;
                let learning_transport = connection.clone();
                let mut http3: h3::server::Connection<_, bytes::Bytes> =
                    h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
                eprintln!("pinned QUIC ({during_start}): learning H3 ready");
                tokio::select! {
                    biased;
                    complete = learning_complete => complete?,
                    request = http3.accept() => {
                        request.map_err(|error| format!("learning ended before the ticket signal: {error}"))?;
                        return Err("learning ended or sent an origin request".into());
                    }
                }
                learning_transport.close(0_u32.into(), b"ticket learned");
                drop(http3);
                let incoming = endpoint.accept().await.ok_or("second endpoint closed")?;
                eprintln!("pinned QUIC ({during_start}): changed peer accepted");
                assert!(incoming.await.is_err(), "changed leaf passed the old pin");
                eprintln!("pinned QUIC ({during_start}): changed peer rejected");
                TestResult::Ok(())
            };
            let caller = async {
                eprintln!("pinned QUIC ({during_start}): connecting to learn");
                let learning = early_data::connect(&connector, address).await?;
                eprintln!("pinned QUIC ({during_start}): learning connected");
                early_data::wait_for_ticket(&connector).await?;
                eprintln!("pinned QUIC ({during_start}): ticket received");
                // A new server configuration rejects the old ticket. Its new
                // leaf is trusted normally but is outside the immutable pins.
                endpoint.set_server_config(Some(early_data::server_config(&changed, false)?));
                learned.send(()).map_err(|_| "learning peer stopped")?;
                drop(learning);
                assert!(connector.has_ticket_for(TEST_SERVER_NAME));
                let connected = early_data::connect(&connector, address).await;
                eprintln!("pinned QUIC ({during_start}): changed connect returned");
                let error = match connected {
                    Err(error) => error,
                    Ok(connection) => {
                        assert!(
                            !during_start,
                            "the forced initialization race returned a connection"
                        );
                        assert!(connection.sent_early_data());
                        early_data::send(
                            &connector,
                            &connection,
                            http::Method::GET,
                            "/must-not-send",
                            None,
                        )
                        .await
                        .err()
                        .ok_or("pin rejection produced a response")?
                    }
                };
                assert_eq!(
                    pin_error(error.as_ref()),
                    Some(TlsErrorKind::SpkiPinMismatch)
                );
                TestResult::Ok(())
            };
            let result = tokio::try_join!(caller, peer);
            endpoint.close(0_u32.into(), b"test complete");
            result.map(|_| ())
        })
        .await??;
    }
    Ok(())
}
