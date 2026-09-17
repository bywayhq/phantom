use std::time::{Duration, Instant};

use phantom::{HttpProtocol, Session, SseErrorKind, SseEventSource};

use super::{BoxError, Context, endpoint, invalid_data};

pub(super) async fn accept_header(context: &Context) -> Result<(), BoxError> {
    let mut source = connect(
        &context.client.session(),
        context,
        "/eventsource/resources/accept.event_stream",
        &[("pipe", "sub")],
        0,
    )
    .await?;
    expect_next(&mut source, "text/event-stream", "").await?;
    source.close();
    Ok(())
}

pub(super) async fn cache_control(context: &Context) -> Result<(), BoxError> {
    let session = context.client.session();
    for _ in 0..2 {
        let mut source = connect(
            &session,
            context,
            "/eventsource/resources/cache-control.event_stream",
            &[("pipe", "sub")],
            0,
        )
        .await?;
        expect_next(&mut source, "no-cache", "").await?;
        source.close();
    }
    Ok(())
}

pub(super) async fn last_event_id(context: &Context) -> Result<(), BoxError> {
    let mut source = connect(
        &context.client.session(),
        context,
        "/eventsource/resources/last-event-id.py",
        &[],
        1,
    )
    .await?;
    expect_next(&mut source, "hello", "…").await?;
    expect_next(&mut source, "…", "…").await?;
    if source.reconnects() != 1 {
        return Err(invalid_data("Last-Event-ID case did not reconnect once").into());
    }
    source.close();
    Ok(())
}

pub(super) async fn nul_id(context: &Context, value: &str) -> Result<(), BoxError> {
    let mut source = connect(
        &context.client.session(),
        context,
        "/eventsource/resources/last-event-id.py",
        &[("idvalue", value)],
        1,
    )
    .await?;
    expect_next(&mut source, "hello", "").await?;
    expect_next(&mut source, "hello", "").await?;
    if source.reconnects() != 1 {
        return Err(invalid_data("NUL ID case did not reconnect once").into());
    }
    source.close();
    Ok(())
}

pub(super) async fn unterminated_event(context: &Context) -> Result<(), BoxError> {
    let message = "retry:1000\ndata:test1\n\nid:test\ndata:test2";
    let mut source = connect(
        &context.client.session(),
        context,
        "/eventsource/resources/message.py",
        &[("newline", "none"), ("message", message)],
        1,
    )
    .await?;
    expect_next(&mut source, "test1", "").await?;
    expect_next(&mut source, "test1", "").await?;
    if source.last_event_id() != "" {
        return Err(invalid_data("unterminated event committed its ID").into());
    }
    source.close();
    Ok(())
}

pub(super) async fn bogus_retry(context: &Context) -> Result<(), BoxError> {
    let mut source = connect(
        &context.client.session(),
        context,
        "/eventsource/resources/message.py",
        &[("message", "retry:3000\nretry:1000x\ndata:x")],
        1,
    )
    .await?;
    expect_next(&mut source, "x", "").await?;
    if source.retry_delay() != Duration::from_secs(3) {
        return Err(invalid_data(format!(
            "bogus retry changed delay to {:?}",
            source.retry_delay()
        ))
        .into());
    }

    let started = Instant::now();
    expect_next(&mut source, "x", "").await?;
    let elapsed = started.elapsed();
    if !(Duration::from_millis(2250)..Duration::from_millis(3750)).contains(&elapsed) {
        return Err(invalid_data(format!(
            "reconnect delay was {elapsed:?}; expected 3 seconds ±25%"
        ))
        .into());
    }
    source.close();
    Ok(())
}

pub(super) async fn status(context: &Context, status: u16) -> Result<(), BoxError> {
    let url = endpoint(
        &context.base_url,
        "/eventsource/resources/status-error.py",
        &[("status", &status.to_string())],
    )?;
    let result = context
        .client
        .session()
        .event_source(HttpProtocol::Http1, url.as_str())?
        .max_reconnects(0)
        .connect()
        .await;

    if status == 204 {
        let response = result?;
        if !response.body().is_closed() {
            return Err(invalid_data("204 response did not close EventSource").into());
        }
        return Ok(());
    }

    let error = result
        .err()
        .ok_or_else(|| invalid_data(format!("status {status} was accepted")))?;
    if error.kind() != SseErrorKind::UnexpectedStatus {
        return Err(invalid_data(format!("status {status} returned {:?}", error.kind())).into());
    }
    Ok(())
}

async fn connect(
    session: &Session,
    context: &Context,
    path: &str,
    query: &[(&str, &str)],
    max_reconnects: usize,
) -> Result<SseEventSource, BoxError> {
    let url = endpoint(&context.base_url, path, query)?;
    let response = session
        .event_source(HttpProtocol::Http1, url.as_str())?
        .max_reconnects(max_reconnects)
        .connect()
        .await?;
    Ok(response.into_body())
}

async fn expect_next(source: &mut SseEventSource, data: &str, id: &str) -> Result<(), BoxError> {
    let event = source
        .next_event()
        .await?
        .ok_or_else(|| invalid_data("event source ended early"))?;
    if event.data() != data || event.event() != "message" || event.id() != id {
        return Err(invalid_data(format!(
            "received event data={:?} type={:?} id={:?}; expected data={data:?} type=\"message\" id={id:?}",
            event.data(),
            event.event(),
            event.id()
        ))
        .into());
    }
    Ok(())
}
