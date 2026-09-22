# Content decoding

By default Phantom returns the response body exactly as it arrived on the
wire, still compressed if the server compressed it. This guide shows how to
opt into decompression.

## Why decoding is opt-in

Phantom never inserts, removes, or moves `Accept-Encoding`. The field's
presence and its position among the other request fields are part of a
browser's fingerprint, so they belong to the caller or profile. Decoding
therefore accepts only codings the request itself advertised.

## Enable decoding for one request

`RequestBuilder::content_decoding(ContentDecoding::advertised(max))` opts one
request into streaming decoding of `gzip` (and `x-gzip`), `deflate`, `br`, and
`zstd`:

```rust
use phantom::{Client, ContentDecoding, HttpProtocol, RequestError, RequestHeader};

async fn fetch(client: &Client) -> Result<bytes::Bytes, RequestError> {
    let response = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .header(RequestHeader::new("accept-encoding", "gzip, br"))
        .content_decoding(ContentDecoding::advertised(8 << 20))
        .send()
        .await?;
    response.into_body().collect_with_limit(8 << 20).await
}
```

Only codings the request's own ordered `Accept-Encoding` fields advertise are
accepted:

- an explicit member with a nonzero weight; or
- a nonzero `*` for a coding without an explicit member.

An explicit `q=0` withdraws a coding. With decoding enabled, a malformed
`Accept-Encoding` fails before any network I/O with
`RequestErrorKind::InvalidHeader`. The request head is byte-identical with and
without decoding.

## Failures

Decoding fails closed with `RequestErrorKind::ContentDecoding` on the first body
poll, with status and fields still visible, for:

- an unknown coding, including `compress`, `dcb`, and `dcz`;
- a supported coding the request did not advertise;
- `identity` mixed with a coding, or more than three stacked codings;
- malformed or truncated coded data, checksum mismatches, or bytes after a
  complete gzip member, zlib/raw DEFLATE stream, or Brotli stream;
- zstd frames that are not RFC 8878 or need a window above 8 MiB.

Stacked codings decode in reverse application order. `deflate` selects zlib
when the first two bytes form a valid zlib header and raw DEFLATE otherwise.

These rules are deliberately stricter than browsers, which pass unknown
chains through or discard trailing bytes.

## Size limits and backpressure

`max` is an inclusive cap on decoded bytes; exceeding it fails the body with
`RequestErrorKind::ResponseBodyLimit` and cancels the stream.
`collect_with_limit` separately counts the decoded bytes it returns.

Decoded data frames are at most 16 KiB, and the transport is polled only after
buffered input is consumed, preserving backpressure. Decoded frames count as
body activity and are checked against the total deadline.

## What the response shows

- `ResponseInfo::decoded_content_codings` lists the codings applied, in
  `Content-Encoding` order.
- Response fields remain the wire view: `Content-Encoding` and
  `Content-Length` are unchanged, and `Content-Length` still describes encoded
  bytes.
- The size hint becomes unknown while decoding.
- Trailers pass through after all decoded data.
- Only the response returned by `send` is decoded; intermediate redirect
  bodies are dropped undecoded.
- HEAD, 204, 304, and already-empty bodies are never validated or decoded.

SSE responses must not be content-encoded even when decoding is enabled; see
[Server-sent events](sse.md#reading-a-response).

[Content-decoding evidence](../explanation/validation.md#content-decoding-evidence)
lists the tests behind this behavior.
