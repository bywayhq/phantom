use super::*;
use http_body_util::BodyExt;
use std::time::Duration;

#[tokio::test]
async fn writes_wait_for_body_consumption_and_preserve_final_data_before_error()
-> Result<(), Failure> {
    let owner = Upload::new(1, None);
    let mut body = owner.body()?;
    assert!(body.size_hint().exact().is_none());
    let writing = owner.write(Bytes::from_static(b"final bytes"), None);
    tokio::pin!(writing);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut writing)
            .await
            .is_err()
    );
    let frame = body
        .frame()
        .await
        .ok_or_else(|| Failure::new("missing_frame"))?
        .map_err(|_| Failure::new("unexpected_body_error"))?;
    assert_eq!(
        frame
            .into_data()
            .map_err(|_| Failure::new("missing_data"))?,
        "final bytes"
    );
    writing.await?;
    let failing = owner.write(Bytes::new(), Some(true));
    let reading = body.frame();
    let (sent, frame) = tokio::join!(failing, reading);
    sent?;
    assert!(frame.is_some_and(|frame| frame.is_err()));
    assert!(body.is_end_stream());
    assert!(body.frame().await.is_none());
    Ok(())
}

#[tokio::test]
async fn exact_zero_still_requires_terminal_frame_when_polled() -> Result<(), Failure> {
    let owner = Upload::new(1, Some(0));
    let mut body = owner.body()?;
    assert_eq!(body.size_hint().exact(), Some(0));
    assert!(!body.is_end_stream());
    let finishing = owner.write(Bytes::new(), Some(false));
    let reading = body.frame();
    let (sent, frame) = tokio::join!(finishing, reading);
    sent?;
    assert!(frame.is_none());
    assert!(body.is_end_stream());
    owner.closed().await;
    Ok(())
}

#[tokio::test]
async fn dropping_or_closing_body_wakes_unconsumed_writer_and_terminal_waiter()
-> Result<(), Failure> {
    for explicit in [false, true] {
        let owner = Upload::new(1, None);
        let body = owner.body()?;
        let writing = owner.write(Bytes::from_static(b"waiting"), None);
        tokio::pin!(writing);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut writing)
                .await
                .is_err()
        );
        if explicit {
            owner.close();
        } else {
            drop(body);
        }
        assert_eq!(
            writing.await.err().map(|failure| failure.kind),
            Some("upload_closed")
        );
        tokio::time::timeout(Duration::from_secs(1), owner.closed())
            .await
            .map_err(|_| Failure::new("missing_terminal_notification"))?;
        assert!(owner.body().is_err());
    }
    Ok(())
}

#[tokio::test]
async fn owners_are_one_shot_and_other_uploads_survive_close() -> Result<(), Failure> {
    let first = Upload::new(1, None);
    let second = Upload::new(1, Some(2));
    let body = first.body()?;
    assert_eq!(
        first.body().err().map(|failure| failure.kind),
        Some("upload_used")
    );
    drop(body);
    let mut sibling = second.body()?;
    let sending = second.write(Bytes::from_static(b"ok"), None);
    let (sent, frame) = tokio::join!(sending, sibling.frame());
    sent?;
    assert!(frame.is_some_and(|frame| frame.is_ok()));
    assert_eq!(sibling.size_hint().exact(), Some(0));
    assert!(!sibling.is_end_stream());
    Ok(())
}

#[tokio::test]
async fn deadline_closes_without_response_polling_and_reports_total_timeout() -> Result<(), Failure>
{
    let owner = Upload::new(1, None);
    let mut body = owner.body()?;
    owner.deadline(
        &tokio::runtime::Handle::current(),
        Some(Duration::from_millis(10)),
    )?;
    tokio::time::timeout(Duration::from_secs(1), owner.closed())
        .await
        .map_err(|_| Failure::new("missing_deadline_notification"))?;
    let failure = owner.failure(Failure::new("request_body"));
    assert_eq!(failure.kind, "timeout");
    assert_eq!(failure.timeout_phase, Some("total"));
    assert!(body.frame().await.is_some_and(|frame| frame.is_err()));
    Ok(())
}

#[tokio::test]
async fn successful_close_cancels_the_timer_and_releases_its_owner() -> Result<(), Failure> {
    let owner = Upload::new(1, None);
    let weak = Arc::downgrade(&owner);
    owner.deadline(
        &tokio::runtime::Handle::current(),
        Some(Duration::from_secs(60)),
    )?;
    owner.close();
    assert_eq!(
        owner.failure(Failure::new("request_body")).kind,
        "request_body"
    );
    drop(owner);
    tokio::time::timeout(Duration::from_secs(1), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| Failure::new("timer_retained_owner"))?;
    Ok(())
}
