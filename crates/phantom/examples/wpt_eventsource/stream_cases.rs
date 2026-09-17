use phantom::{HttpProtocol, SseErrorKind, SseEvent, SseStream};

use super::{BoxError, Context, endpoint, invalid_data};

pub(super) async fn event_data(context: &Context) -> Result<(), BoxError> {
    let events = take_events(context, "/eventsource/resources/message2.py", &[], 3).await?;
    expect_event(&events[0], "msg\nmsg", "message", "")?;
    expect_event(&events[1], "", "message", "")?;
    expect_event(&events[2], "end", "message", "")
}

pub(super) async fn field_parsing(context: &Context) -> Result<(), BoxError> {
    let message = "data:\0\ndata:  2\rData:1\ndata\0:2\ndata:1\r\0data:4\nda-ta:3\rdata_5\ndata:3\rdata:\r\n data:32\ndata:4\n";
    let events = all_events(
        context,
        "/eventsource/resources/message.py",
        &[("message", message), ("newline", "none")],
        2,
    )
    .await?;
    expect_count(&events, 1)?;
    expect_event(&events[0], "\0\n 2\n1\n3\n\n4", "message", "")
}

pub(super) async fn event_name(context: &Context) -> Result<(), BoxError> {
    let events = all_events(
        context,
        "/eventsource/resources/message.py",
        &[("message", "event:test\ndata:x\n\ndata:x")],
        3,
    )
    .await?;
    expect_count(&events, 2)?;
    expect_event(&events[0], "x", "test", "")?;
    expect_event(&events[1], "x", "message", "")
}

pub(super) async fn newlines(context: &Context) -> Result<(), BoxError> {
    let events = all_events(
        context,
        "/eventsource/resources/message.py",
        &[
            ("message", "data:test\r\ndata\ndata:test\r\n\r"),
            ("newline", "none"),
        ],
        2,
    )
    .await?;
    expect_count(&events, 1)?;
    expect_event(&events[0], "test\n\ntest", "message", "")
}

pub(super) async fn bom(context: &Context) -> Result<(), BoxError> {
    let events = all_events(
        context,
        "/eventsource/resources/message.py",
        &[("message", "\u{feff}data:1\n\n\u{feff}data:2\n\ndata:3")],
        3,
    )
    .await?;
    expect_data(&events, &["1", "3"])
}

pub(super) async fn double_bom(context: &Context) -> Result<(), BoxError> {
    let events = all_events(
        context,
        "/eventsource/resources/message.py",
        &[("message", "\u{feff}\u{feff}data:1\n\ndata:2\n\ndata:3")],
        3,
    )
    .await?;
    expect_data(&events, &["2", "3"])
}

pub(super) async fn mime_trailing_semicolon(context: &Context) -> Result<(), BoxError> {
    let events = all_events(
        context,
        "/eventsource/resources/message.py",
        &[("mime", "text/event-stream;")],
        2,
    )
    .await?;
    expect_data(&events, &["data"])
}

pub(super) async fn invalid_mime(context: &Context) -> Result<(), BoxError> {
    let url = endpoint(
        &context.base_url,
        "/eventsource/resources/message.py",
        &[("mime", "text/x-bogus")],
    )?;
    let response = context
        .client
        .get(HttpProtocol::Http1, url.as_str())?
        .send()
        .await?;
    let error = match SseStream::from_response(response) {
        Ok(_) => return Err(invalid_data("invalid MIME type was accepted").into()),
        Err(error) => error,
    };
    if error.kind() != SseErrorKind::InvalidContentType {
        return Err(invalid_data(format!("invalid MIME type returned {:?}", error.kind())).into());
    }
    Ok(())
}

pub(super) async fn utf8(context: &Context) -> Result<(), BoxError> {
    let events = all_events(
        context,
        "/eventsource/resources/message.py",
        &[
            ("mime", "text/event-stream;charset=windows-1252"),
            ("message", "data:ok…"),
        ],
        2,
    )
    .await?;
    expect_data(&events, &["ok…"])
}

pub(super) async fn id_persists(context: &Context) -> Result<(), BoxError> {
    let events = all_events(
        context,
        "/eventsource/resources/last-event-id2.py",
        &[("type", "1")],
        5,
    )
    .await?;
    expect_count(&events, 4)?;
    for (index, event) in events.iter().enumerate() {
        let data = ["1", "2", "3", "4"][index];
        let id = ["1", "1", "2", "2"][index];
        expect_event(event, data, "message", id)?;
    }
    Ok(())
}

pub(super) async fn id_resets(context: &Context, kind: &str) -> Result<(), BoxError> {
    let events = all_events(
        context,
        "/eventsource/resources/last-event-id2.py",
        &[("type", kind)],
        4,
    )
    .await?;
    expect_count(&events, 3)?;
    expect_event(&events[0], "1", "message", "1")?;
    expect_event(&events[1], "2", "message", "")?;
    expect_event(&events[2], "3", "message", "")
}

async fn take_events(
    context: &Context,
    path: &str,
    query: &[(&str, &str)],
    count: usize,
) -> Result<Vec<SseEvent>, BoxError> {
    let mut stream = open_stream(context, path, query).await?;
    let mut events = Vec::with_capacity(count);
    while events.len() < count {
        events.push(
            stream
                .next_event()
                .await?
                .ok_or_else(|| invalid_data("event stream ended early"))?,
        );
    }
    Ok(events)
}

async fn all_events(
    context: &Context,
    path: &str,
    query: &[(&str, &str)],
    maximum: usize,
) -> Result<Vec<SseEvent>, BoxError> {
    let mut stream = open_stream(context, path, query).await?;
    let mut events = Vec::new();
    while let Some(event) = stream.next_event().await? {
        if events.len() == maximum {
            return Err(invalid_data("event stream exceeded the case bound").into());
        }
        events.push(event);
    }
    Ok(events)
}

async fn open_stream(
    context: &Context,
    path: &str,
    query: &[(&str, &str)],
) -> Result<SseStream, BoxError> {
    let url = endpoint(&context.base_url, path, query)?;
    let response = context
        .client
        .get(HttpProtocol::Http1, url.as_str())?
        .send()
        .await?;
    Ok(SseStream::from_response(response)?.into_body())
}

fn expect_count(events: &[SseEvent], expected: usize) -> Result<(), BoxError> {
    if events.len() != expected {
        return Err(invalid_data(format!(
            "received {} events; expected {expected}",
            events.len()
        ))
        .into());
    }
    Ok(())
}

fn expect_data(events: &[SseEvent], expected: &[&str]) -> Result<(), BoxError> {
    expect_count(events, expected.len())?;
    for (event, data) in events.iter().zip(expected) {
        expect_event(event, data, "message", "")?;
    }
    Ok(())
}

fn expect_event(event: &SseEvent, data: &str, event_type: &str, id: &str) -> Result<(), BoxError> {
    if event.data() != data || event.event() != event_type || event.id() != id {
        return Err(invalid_data(format!(
            "received event data={:?} type={:?} id={:?}; expected data={data:?} type={event_type:?} id={id:?}",
            event.data(),
            event.event(),
            event.id()
        ))
        .into());
    }
    Ok(())
}
