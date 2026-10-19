use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use http_body::Body;
use phantom_net::{
    http1::Http1Connection,
    request::{OriginForm, RequestHeader},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ResponseBody, checked_body_length};
use crate::{
    ContentDecoding, HttpProtocol, RequestErrorKind, RequestTimeouts, TimeoutPhase,
    content_coding::{AdvertisedContentCodings, ContentDecodingPlan, Pump, plan},
    timeout::TimeoutBudget,
};

#[tokio::test(start_paused = true)]
async fn stacked_header_work_yields_then_observes_the_total_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    // Valid empty gzip: FNAME, a long nonzero name, then empty DEFLATE
    // and the zero CRC32/ISIZE footer. Only intermediate bytes expand.
    let mut gzip = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 255];
    gzip.resize(10 + (4 << 20), b'n');
    gzip.push(0);
    gzip.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let encoded = zstd::encode_all(gzip.as_slice(), 3)?;
    let advertised = AdvertisedContentCodings::from_request_headers(&[RequestHeader::new(
        "accept-encoding",
        "gzip, zstd",
    )])?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static("gzip, zstd"),
    );

    let mut decoder = match plan(
        ContentDecoding::advertised(0),
        advertised,
        &Method::GET,
        StatusCode::OK,
        &headers,
        false,
        HttpProtocol::Http1,
    ) {
        ContentDecodingPlan::Decode(decoder, _) => decoder,
        ContentDecodingPlan::Reject(error) => return Err(error.into()),
        ContentDecodingPlan::Passthrough => return Err("stacked body was not decoded".into()),
    };
    decoder.push(Bytes::from(encoded));
    decoder.end_input();
    let mut body = ResponseBody {
        activity: None,
        diagnostics: phantom_net::request_diagnostics::PhaseObservation::begin(
            crate::RequestTimingPhase::ResponseBody,
            None,
        ),
        inner: None,
        timeouts: None,
        content: None,
        held_trailers: None,
        origin: None,
        proxy_authentication: None,
    };
    body.decode_content(decoder);
    body.apply_timeouts(
        TimeoutBudget::new(RequestTimeouts::new().total(Duration::from_secs(1)))?,
        HttpProtocol::Http1,
    )?;

    struct WakeFlag(AtomicBool);

    impl Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let wake = Arc::new(WakeFlag(AtomicBool::new(false)));
    let waker = Waker::from(Arc::clone(&wake));
    let mut context = Context::from_waker(&waker);
    let first = Pin::new(&mut body).poll_frame(&mut context);
    assert!(
        first.is_pending(),
        "stacked header work finished in one poll: {first:?}"
    );
    assert!(!body.is_end_stream());
    assert!(
        wake.0.load(Ordering::SeqCst),
        "buffered header yield did not wake its caller"
    );

    tokio::time::advance(Duration::from_secs(2)).await;
    let result = Pin::new(&mut body).poll_frame(&mut context);
    let Poll::Ready(Some(Err(error))) = result else {
        panic!("yielded header work escaped the total deadline: {result:?}");
    };
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
    assert!(body.is_end_stream());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn buffered_wire_data_cannot_outlive_the_total_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let mut body = buffered_wire_body(RequestTimeouts::new().total(Duration::from_secs(1))).await?;

    tokio::time::advance(Duration::from_secs(2)).await;
    let mut context = Context::from_waker(Waker::noop());
    let result = Pin::new(&mut body).poll_frame(&mut context);

    let Poll::Ready(Some(Err(error))) = result else {
        panic!("buffered data escaped the total deadline: {result:?}");
    };
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
    assert!(body.is_end_stream());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn ready_wire_data_satisfies_an_expired_idle_limit() -> Result<(), Box<dyn std::error::Error>>
{
    for idle in [Duration::ZERO, Duration::from_secs(1)] {
        let mut body = buffered_wire_body(
            RequestTimeouts::new()
                .read_idle(idle)
                .total(Duration::from_secs(10)),
        )
        .await?;

        tokio::time::advance(Duration::from_secs(2)).await;
        let mut context = Context::from_waker(Waker::noop());
        let result = Pin::new(&mut body).poll_frame(&mut context);

        let Poll::Ready(Some(Ok(frame))) = result else {
            panic!("ready data failed its idle limit: {result:?}");
        };
        assert_eq!(frame.into_data().map_err(|_| "expected data")?, "ok");
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn ready_decoded_eof_at_work_quotas_wins_idle_but_preserves_total()
-> Result<(), Box<dyn std::error::Error>> {
    for eof_at_facade_yield in [false, true] {
        for idle in [Duration::ZERO, Duration::from_secs(1)] {
            for total_expired in [false, true] {
                let mut body = gzip_body_at_work_quota(eof_at_facade_yield)?;
                let total = if total_expired { 1 } else { 10 };
                body.apply_timeouts(
                    TimeoutBudget::new(
                        RequestTimeouts::new()
                            .read_idle(idle)
                            .total(Duration::from_secs(total)),
                    )?,
                    HttpProtocol::Http1,
                )?;

                tokio::time::advance(Duration::from_secs(2)).await;
                let mut context = Context::from_waker(Waker::noop());
                let result = if eof_at_facade_yield {
                    let Some(super::ContentState::Decode(decoder)) = body.content.as_mut() else {
                        return Err("quota body lost its actual decoder".into());
                    };
                    // Exercise the actual quota exit with freshly recorded EOF.
                    decoder.end_input();
                    body.yield_decoding(&mut context)
                } else {
                    Pin::new(&mut body).poll_frame(&mut context)
                };

                if total_expired {
                    let Poll::Ready(Some(Err(error))) = result else {
                        panic!("ready quota EOF escaped total: {result:?}");
                    };
                    assert_eq!(error.kind(), RequestErrorKind::Timeout);
                    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
                } else {
                    assert!(
                        matches!(result, Poll::Ready(None)),
                        "ready quota EOF lost to idle: {result:?}"
                    );
                }
                assert!(body.is_end_stream());
            }
        }
    }
    Ok(())
}

fn gzip_body_at_work_quota(
    eof_at_facade_yield: bool,
) -> Result<ResponseBody, Box<dyn std::error::Error>> {
    // Eight full stage inputs, with the empty member's footer at the end.
    let mut gzip = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 255];
    gzip.resize(8 * 16 * 1024 - 11, b'n');
    gzip.push(0);
    gzip.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let advertised = AdvertisedContentCodings::from_request_headers(&[RequestHeader::new(
        "accept-encoding",
        "gzip",
    )])?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    let mut decoder = match plan(
        ContentDecoding::advertised(0),
        advertised,
        &Method::GET,
        StatusCode::OK,
        &headers,
        false,
        HttpProtocol::Http1,
    ) {
        ContentDecodingPlan::Decode(decoder, _) => decoder,
        ContentDecodingPlan::Reject(error) => return Err(error.into()),
        ContentDecodingPlan::Passthrough => return Err("quota gzip was not decoded".into()),
    };
    decoder.push(Bytes::from(gzip));

    if eof_at_facade_yield {
        let mut needs_input = false;
        for _ in 0..2 {
            match decoder.pump()? {
                Pump::Yield => {}
                Pump::NeedInput => {
                    needs_input = true;
                    break;
                }
                other => return Err(format!("quota setup returned {other:?}").into()),
            }
        }
        assert!(needs_input, "actual quota decoder did not drain before EOF");
    } else {
        decoder.end_input();
    }

    let mut body = ResponseBody {
        activity: None,
        diagnostics: phantom_net::request_diagnostics::PhaseObservation::begin(
            crate::RequestTimingPhase::ResponseBody,
            None,
        ),
        inner: None,
        timeouts: None,
        content: None,
        held_trailers: None,
        origin: None,
        proxy_authentication: None,
    };
    body.decode_content(decoder);
    Ok(body)
}

async fn buffered_wire_body(
    policy: RequestTimeouts,
) -> Result<super::ResponseBody, Box<dyn std::error::Error>> {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let server = tokio::spawn(async move {
        let mut head = Vec::new();
        loop {
            head.push(peer.read_u8().await?);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await?;
        Ok::<_, std::io::Error>(())
    });
    let connection = Http1Connection::connect(stream).await?;
    let response = connection
        .send_get(
            OriginForm::parse("/")?,
            vec![RequestHeader::new("Host", "example.test")],
        )
        .await?;
    server.await??;
    let mut body = super::ResponseBody::http1(response.into_body());
    body.apply_timeouts(TimeoutBudget::new(policy)?, HttpProtocol::Http1)?;
    Ok(body)
}

#[test]
fn collection_limit_is_inclusive() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(checked_body_length(3, 2, 5)?, 5);
    Ok(())
}

#[test]
fn collection_limit_rejects_excess_and_arithmetic_overflow() {
    let Err(excess) = checked_body_length(3, 3, 5) else {
        panic!("excess length was accepted");
    };
    assert_eq!(excess.kind(), RequestErrorKind::ResponseBodyLimit);

    let Err(overflow) = checked_body_length(usize::MAX, 1, usize::MAX) else {
        panic!("overflowing length was accepted");
    };
    assert_eq!(overflow.kind(), RequestErrorKind::ResponseBodyLimit);
}
