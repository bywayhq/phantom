use std::hint::black_box;

use bytes::Bytes;
use criterion::{BatchSize, Criterion, Throughput};
use http_body_util::BodyExt;
use phantom_net::http1::{Http1TlsConnector, OriginForm, RequestHeader, send_get};
use phantom_profile::chromium::v152_macos_tls;

use super::{BODY_BYTES, replay_stream::ReplayStream, runtime};

pub(super) fn register(criterion: &mut Criterion) {
    tls_connector(criterion);
    response_head(criterion);
    content_length(criterion);
    chunked(criterion);
}

fn tls_connector(criterion: &mut Criterion) {
    let settings = v152_macos_tls();
    criterion.bench_function("tls_connector/chromium_reference", |bencher| {
        bencher.iter(|| match Http1TlsConnector::new(black_box(&settings)) {
            Ok(connector) => black_box(connector),
            Err(error) => panic!("reference TLS settings failed: {error}"),
        });
    });
}

fn response_head(criterion: &mut Criterion) {
    let runtime = runtime();
    let response = Bytes::from_static(b"HTTP/1.1 204 No Content\r\n\r\n");
    let target = target();
    let headers = twelve_headers();

    criterion.bench_function("http1/response_head/12_headers", |bencher| {
        bencher.to_async(&runtime).iter_batched(
            || {
                (
                    ReplayStream::new(response.clone()),
                    target.clone(),
                    headers.clone(),
                )
            },
            |(stream, target, headers)| async move {
                let response = match send_get(stream, target, headers).await {
                    Ok(response) => response,
                    Err(error) => panic!("HTTP/1 response-head benchmark failed: {error}"),
                };
                match response.into_body().collect().await {
                    Ok(collected) => black_box(collected),
                    Err(error) => panic!("HTTP/1 response body failed: {error}"),
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn content_length(criterion: &mut Criterion) {
    let runtime = runtime();
    let response = content_length_response();
    let target = target();
    let headers = twelve_headers();
    let mut group = criterion.benchmark_group("http1/content_length");
    group.throughput(Throughput::Bytes(BODY_BYTES as u64));
    group.bench_function(BODY_BYTES.to_string(), |bencher| {
        bencher.to_async(&runtime).iter_batched(
            || {
                (
                    ReplayStream::new(response.clone()),
                    target.clone(),
                    headers.clone(),
                )
            },
            collect_response,
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn chunked(criterion: &mut Criterion) {
    let runtime = runtime();
    let response = chunked_response();
    let target = target();
    let headers = twelve_headers();
    let mut group = criterion.benchmark_group("http1/chunked");
    group.throughput(Throughput::Bytes(BODY_BYTES as u64));
    group.bench_function(BODY_BYTES.to_string(), |bencher| {
        bencher.to_async(&runtime).iter_batched(
            || {
                (
                    ReplayStream::new(response.clone()),
                    target.clone(),
                    headers.clone(),
                )
            },
            collect_response,
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

async fn collect_response(
    (stream, target, headers): (ReplayStream, OriginForm, Vec<RequestHeader>),
) -> Bytes {
    let response = match send_get(stream, target, headers).await {
        Ok(response) => response,
        Err(error) => panic!("HTTP/1 benchmark failed before the body: {error}"),
    };
    match response.into_body().collect().await {
        Ok(collected) => black_box(collected.to_bytes()),
        Err(error) => panic!("HTTP/1 benchmark body failed: {error}"),
    }
}

fn target() -> OriginForm {
    match OriginForm::parse("/resource?item=1") {
        Ok(target) => target,
        Err(error) => panic!("fixed benchmark target is invalid: {error}"),
    }
}

fn twelve_headers() -> Vec<RequestHeader> {
    vec![
        RequestHeader::new("Host", "example.test"),
        RequestHeader::new("Connection", "keep-alive"),
        RequestHeader::new("sec-ch-ua", "\"Chromium\";v=\"150\""),
        RequestHeader::new("sec-ch-ua-mobile", "?0"),
        RequestHeader::new("sec-ch-ua-platform", "\"Linux\""),
        RequestHeader::new("Upgrade-Insecure-Requests", "1"),
        RequestHeader::new("User-Agent", "phantom-benchmark"),
        RequestHeader::new("Accept", "text/html,application/xhtml+xml"),
        RequestHeader::new("Sec-Fetch-Site", "none"),
        RequestHeader::new("Sec-Fetch-Mode", "navigate"),
        RequestHeader::new("Accept-Encoding", "gzip, deflate, br"),
        RequestHeader::new("Accept-Language", "en-US,en;q=0.9"),
    ]
}

fn content_length_response() -> Bytes {
    let mut response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY_BYTES}\r\n\r\n").into_bytes();
    response.resize(response.len() + BODY_BYTES, b'x');
    response.into()
}

fn chunked_response() -> Bytes {
    let mut response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Final\r\n\r\n".to_vec();
    for _ in 0..16 {
        response.extend_from_slice(b"1000\r\n");
        response.resize(response.len() + 4096, b'x');
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"0\r\nX-Final: yes\r\n\r\n");
    response.into()
}
