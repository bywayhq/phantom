# Content decoding

Phantom returns each response body exactly as the server sent it, still
compressed if the server compressed it. You can turn on decompression for
individual requests.

## Why decoding is opt-in

Phantom never adds, removes, or moves `Accept-Encoding` by itself. Whether a
browser sends that field, and where it sits among the other fields, is part of
its fingerprint, so the field is yours to set, directly or through a
[request template](profiles.md#request-templates). Decoding then accepts only
the codings that field advertised.

## Enable decoding for a request

`RequestBuilder::content_decoding(ContentDecoding::advertised(max))` turns on
streaming decoding of `gzip` (and its alias `x-gzip`), `deflate`, `br`
(Brotli), and `zstd` for one request:

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

The request bytes are identical with and without decoding.

A response may use a coding only if the request's `Accept-Encoding` fields
advertise it, either:

- by name with a nonzero weight, or
- through `*` with a nonzero weight, when the coding is not named.

An explicit `q=0` withdraws a coding. With a template and no `Accept-Encoding`
of your own, the template's captured value is the one that counts.

With decoding on, these fail before any network I/O:

- a malformed `Accept-Encoding`, with `RequestErrorKind::InvalidHeader`;
- a template whose per-protocol field lists carry different
  `Accept-Encoding` values, with `RequestErrorKind::RequestTemplate`.

## Failures

Decoding is strict. It fails with `RequestErrorKind::ContentDecoding` on the
first read of the body, after the status and fields are already available,
when the response has:

- an unknown coding, including `compress`, `dcb`, and `dcz`;
- a supported coding the request did not advertise;
- `identity` combined with another coding, or more than three stacked codings;
- malformed or truncated data, a checksum mismatch, or extra bytes after a
  complete gzip member, zlib or raw DEFLATE stream, or Brotli stream;
- zstd data that is not RFC 8878 frames, or that needs a window larger than
  8 MiB.

Browsers are more lenient: they pass unknown chains through and discard
trailing bytes. Phantom fails instead, so a damaged or unexpected body never
reaches you looking like valid data.

Stacked codings are decoded in the reverse of the order they were applied.
For `deflate`, Phantom decodes zlib when the first two bytes form a valid zlib
header, and raw DEFLATE otherwise.

## Size limits and backpressure

`max` is an inclusive limit on decoded bytes. Going over it fails the body with
`RequestErrorKind::ResponseBodyLimit` and cancels the stream.
`collect_with_limit` applies its own limit to the decoded bytes it returns.

Decoded data arrives in frames of at most 16 KiB. Phantom reads more from the
network only after you consume the data it has already buffered, so
backpressure still works. Decoded frames count as body activity for the
read-idle timeout and are checked against the total deadline.

## What the response shows

- `ResponseInfo::decoded_content_codings` lists the codings that were decoded,
  in `Content-Encoding` order.
- Response fields still show what was on the wire. `Content-Encoding` and
  `Content-Length` are unchanged, and `Content-Length` counts encoded bytes.
- The body's size hint becomes unknown.
- Trailers arrive after all decoded data.
- Only the response that `send` returns is decoded. Bodies of intermediate
  redirect responses are dropped without decoding.
- HEAD responses, 204 and 304 responses, and empty bodies are never checked or
  decoded.

SSE responses must not be content-encoded, even with decoding enabled; see
[Server-sent events](sse.md#reading-a-response).

[Content-decoding evidence](../explanation/validation.md#content-decoding-evidence)
lists the tests behind this behavior.
