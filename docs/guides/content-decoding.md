# Content decoding

Phantom returns each response body as the server sent it, still compressed if
the server compressed it. This guide shows how to decompress the body of one
request.

> For builders who have read [Getting started](../getting-started.md).

## Decompress a response body

Advertise the codings you accept in `Accept-Encoding`, then turn on decoding
for the request:

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

- Phantom never adds, removes, or moves `Accept-Encoding`. Its presence and
  position are part of the [header order](../fingerprinting.md#header-order),
  so you set it, directly or through a
  [request template](profiles.md#request-templates). The request bytes are
  the same with and without decoding.
- Decoding supports `gzip` (and its alias `x-gzip`), `deflate`, `br`, and
  `zstd`, and accepts only codings the request advertised: by name with a
  nonzero weight, or through `*` with a nonzero weight. `q=0` withdraws a
  coding. With a template and no `Accept-Encoding` of your own, the template's
  value counts.
- `max` is an inclusive limit on decoded bytes. Going over it fails the body
  with `RequestErrorKind::ResponseBodyLimit`.

## Check which codings were decoded

`ResponseInfo::decoded_content_codings` lists the codings Phantom removed, in
`Content-Encoding` order:

```rust
use phantom::{
    Client, ContentDecoding, HttpProtocol, RequestError, RequestHeader, ResponseInfo,
};

async fn codings(client: &Client) -> Result<(), RequestError> {
    let response = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .header(RequestHeader::new("accept-encoding", "gzip, deflate, br, zstd"))
        .content_decoding(ContentDecoding::advertised(8 << 20))
        .send()
        .await?;
    if let Some(info) = response.extensions().get::<ResponseInfo>() {
        println!("{:?}", info.decoded_content_codings());
    }
    Ok(())
}
```

The response fields still show what was on the wire: `Content-Encoding` is
unchanged, and `Content-Length` counts encoded bytes. The body's size hint
becomes unknown.

## Limits

- Decoding is strict. The first body read fails with
  `RequestErrorKind::ContentDecoding`, after the status and fields are already
  available, for an unknown coding (including `compress`, `dcb`, and `dcz`), a
  coding the request did not advertise, `identity` combined with another
  coding, more than three stacked codings, malformed or truncated data, a
  checksum mismatch, extra bytes after a complete gzip member, zlib or raw
  DEFLATE stream, or Brotli stream, or zstd data that is not RFC 8878 frames
  or needs a window over 8 MiB. Browsers pass unknown chains
  through and discard trailing bytes.
- With decoding on, a malformed `Accept-Encoding` fails with
  `RequestErrorKind::InvalidHeader`, and a template whose per-protocol field
  lists disagree on `Accept-Encoding` fails with
  `RequestErrorKind::RequestTemplate`. Both fail before network I/O.
- Stacked codings are decoded in reverse order of application. For `deflate`,
  Phantom decodes zlib when the first two bytes form a valid zlib header, and
  raw DEFLATE otherwise.
- Decoded data arrives in frames of at most 16 KiB. Phantom reads from the
  network only after you consume what it has buffered. Decoded frames count
  as body activity for the read-idle timeout and are checked against the total
  deadline.
- `collect_with_limit` applies its own limit to the decoded bytes.
- Trailers arrive after all decoded data.
- Only the response that `send` returns is decoded. Bodies of intermediate
  redirect responses are dropped without decoding.
- HEAD responses, 204 and 304 responses, and empty bodies are never checked or
  decoded.
- SSE responses must not be content-encoded, even with decoding on; see
  [Server-sent events](sse.md#read-an-event-stream).

## Next

- [Defaults and limits](../reference/limits.md): every default, including
  decoding's off state.
- [Content-decoding evidence](../explanation/validation.md#content-decoding-evidence):
  the tests behind this behavior.
- [Profiles](profiles.md#request-templates): templates that set
  `Accept-Encoding` for you.
