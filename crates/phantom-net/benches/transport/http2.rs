use std::hint::black_box;

use bytes::Bytes;
use criterion::{BatchSize, Criterion, Throughput};
use http_body_util::BodyExt;
use phantom_net::http2::{OriginForm, RequestHeader, send_get};
use phantom_profile::{Http2Settings, chromium::v152_macos_http2};
use tokio::runtime::Builder;

use super::{BODY_BYTES, replay_stream::ReplayStream};

const FRAME_PAYLOAD_BYTES: usize = 16 * 1024;
const CONNECTION_PREFACE_BYTES: usize = 24;
const FRAME_HEADER_BYTES: usize = 9;
const SETTING_BYTES: usize = 6;
const WINDOW_UPDATE_PAYLOAD_BYTES: usize = 4;

pub(super) fn register(criterion: &mut Criterion) {
    response_head(criterion);
    streaming_body(criterion);
}

fn response_head(criterion: &mut Criterion) {
    let runtime = runtime();
    let response = response_head_replay();
    let settings = v152_macos_http2();
    let target = target();
    let headers = twelve_ordered_headers();

    criterion.bench_function("http2/response_head/12_ordered_headers", |bencher| {
        bencher.to_async(&runtime).iter_batched(
            || {
                (
                    replay_after_request(response.clone(), &settings),
                    settings.clone(),
                    target.clone(),
                    headers.clone(),
                )
            },
            |input| complete_response(input, 204, 0),
            BatchSize::SmallInput,
        );
    });
}

fn streaming_body(criterion: &mut Criterion) {
    let runtime = runtime();
    let response = streaming_body_replay();
    let settings = v152_macos_http2();
    let target = target();
    let mut group = criterion.benchmark_group("http2/streaming_body");
    group.throughput(Throughput::Bytes(BODY_BYTES as u64));
    group.bench_function(BODY_BYTES.to_string(), |bencher| {
        bencher.to_async(&runtime).iter_batched(
            || {
                (
                    replay_after_request(response.clone(), &settings),
                    settings.clone(),
                    target.clone(),
                    Vec::new(),
                )
            },
            |input| complete_response(input, 200, BODY_BYTES),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

async fn complete_response(
    (stream, settings, target, headers): (
        ReplayStream,
        Http2Settings,
        OriginForm,
        Vec<RequestHeader>,
    ),
    expected_status: u16,
    expected_body_bytes: usize,
) -> Bytes {
    let response = match send_get(stream, &settings, "example.test", target, headers).await {
        Ok(response) => response,
        Err(error) => panic!("HTTP/2 benchmark failed before the body: {error}"),
    };
    assert_eq!(response.status().as_u16(), expected_status);
    let body = match response.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => panic!("HTTP/2 benchmark body failed: {error}"),
    };
    assert_eq!(body.len(), expected_body_bytes);

    // Completing the body starts the one-shot connection shutdown task. Give
    // that already-ready task a turn so iterations do not accumulate drivers.
    tokio::task::yield_now().await;
    black_box(body)
}

fn target() -> OriginForm {
    match OriginForm::parse("/resource?item=1") {
        Ok(target) => target,
        Err(error) => panic!("fixed benchmark target is invalid: {error}"),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    match Builder::new_current_thread().enable_time().build() {
        Ok(runtime) => runtime,
        Err(error) => panic!("failed to build HTTP/2 benchmark runtime: {error}"),
    }
}

fn replay_after_request(response: Bytes, settings: &Http2Settings) -> ReplayStream {
    // Hold the server replay until the write containing the first request byte;
    // each ReplayStream write accepts the complete supplied buffer.
    let initial_settings_bytes =
        FRAME_HEADER_BYTES + SETTING_BYTES * settings.initial_settings.len();
    let connection_window_bytes = usize::from(settings.initial_connection_window_size > 65_535)
        * (FRAME_HEADER_BYTES + WINDOW_UPDATE_PAYLOAD_BYTES);
    let startup_bytes = CONNECTION_PREFACE_BYTES + initial_settings_bytes + connection_window_bytes;

    ReplayStream::after_written_bytes(response, startup_bytes + 1)
}

fn twelve_ordered_headers() -> Vec<RequestHeader> {
    vec![
        RequestHeader::new("accept", "text/html,application/xhtml+xml"),
        RequestHeader::new("sec-ch-ua", "\"Chromium\";v=\"152\""),
        RequestHeader::new("sec-ch-ua-mobile", "?0"),
        RequestHeader::new("sec-ch-ua-platform", "\"macOS\""),
        RequestHeader::new("upgrade-insecure-requests", "1"),
        RequestHeader::new("user-agent", "phantom-benchmark"),
        RequestHeader::new("sec-fetch-site", "none"),
        RequestHeader::new("sec-fetch-mode", "navigate"),
        RequestHeader::new("sec-fetch-user", "?1"),
        RequestHeader::new("sec-fetch-dest", "document"),
        RequestHeader::new("accept-encoding", "gzip, deflate, br, zstd"),
        RequestHeader::new("accept-language", "en-US,en;q=0.9"),
    ]
}

fn response_head_replay() -> Bytes {
    let mut response = Vec::with_capacity(45);
    push_server_preface(&mut response);
    push_frame(&mut response, 1, 0x5, 1, &[0x89]);
    push_graceful_shutdown(&mut response);
    response.into()
}

fn streaming_body_replay() -> Bytes {
    let mut response = Vec::with_capacity(BODY_BYTES + 89);
    push_server_preface(&mut response);
    push_frame(&mut response, 1, 0x4, 1, &[0x88]);

    let payload = vec![b'x'; FRAME_PAYLOAD_BYTES];
    for offset in (0..BODY_BYTES).step_by(FRAME_PAYLOAD_BYTES) {
        let length = FRAME_PAYLOAD_BYTES.min(BODY_BYTES - offset);
        let flags = u8::from(offset + length == BODY_BYTES);
        push_frame(&mut response, 0, flags, 1, &payload[..length]);
    }
    push_graceful_shutdown(&mut response);
    response.into()
}

fn push_server_preface(output: &mut Vec<u8>) {
    push_frame(output, 4, 0, 0, &[]);
    push_frame(output, 4, 0x1, 0, &[]);
}

fn push_graceful_shutdown(output: &mut Vec<u8>) {
    push_frame(output, 7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]);
}

fn push_frame(output: &mut Vec<u8>, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let length = payload.len();
    output.extend_from_slice(&[
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
        kind,
        flags,
    ]);
    output.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    output.extend_from_slice(payload);
}
