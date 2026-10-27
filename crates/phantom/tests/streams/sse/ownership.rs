use phantom::{ResponseTrailers, SseErrorKind, SseLimits, SseStream};

use super::{TestIdentity, TestResult, bounded, fixed_response_observed};

const WITH_TRAILERS: &[u8] = b"HTTP/1.1 200 OK\r\n\
    Content-Type: text/event-stream\r\n\
    Transfer-Encoding: chunked\r\n\r\n\
    9\r\ndata: x\n\n\r\n\
    0\r\nX-One: first\r\nx-one: second\r\n\r\n";

#[tokio::test]
async fn event_eof_retains_ordered_trailers_after_repeated_reads() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let response = fixed_response_observed(&identity, WITH_TRAILERS, None).await?;
        let mut events = SseStream::from_response(response)?.into_body();
        assert_eq!(events.trailers(), &ResponseTrailers::Pending);

        let event = events.next_event().await?.ok_or("missing event")?;
        assert_eq!(event.data(), "x");
        assert_eq!(events.trailers(), &ResponseTrailers::Pending);
        assert_eq!(events.next_event().await?, None);
        assert_eq!(events.next_event().await?, None);

        let ResponseTrailers::Complete(fields) = events.trailers() else {
            return Err("trailers not complete after validated EOF".into());
        };
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.name(), field.value()))
                .collect::<Vec<_>>(),
            [
                ("X-One", b"first".as_slice()),
                ("x-one", b"second".as_slice())
            ]
        );
        let expected = events.trailers().clone();
        assert_eq!(events.into_trailers(), expected);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn abandoning_events_and_decode_failure_do_not_publish_trailers() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let response = fixed_response_observed(&identity, WITH_TRAILERS, None).await?;
        let events = SseStream::from_response(response)?.into_body();
        assert_eq!(events.into_trailers(), ResponseTrailers::Unavailable);

        let response = fixed_response_observed(&identity, WITH_TRAILERS, None).await?;
        let mut events =
            SseStream::from_response_with_limits(response, SseLimits::new(4, 32))?.into_body();
        let error = events
            .next_event()
            .await
            .err()
            .ok_or("oversized SSE line accepted")?;
        assert_eq!(error.kind(), SseErrorKind::LineTooLong);
        assert_eq!(events.next_event().await?, None);
        assert_eq!(events.trailers(), &ResponseTrailers::Unavailable);
        assert_eq!(events.into_trailers(), ResponseTrailers::Unavailable);
        Ok(())
    })
    .await
}
