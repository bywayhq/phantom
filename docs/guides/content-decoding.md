# Content decoding

Phantom gives you each response body as the server sent it. If the server
compressed the body, it stays compressed. Turn on decoding for a request to
get its body decompressed.

## Decompress a response body

List the compressions you accept in an `Accept-Encoding` header, then turn
on decoding for the request.

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

Phantom decodes `gzip`, `deflate`, `br` and `zstd`, but only the ones your
`Accept-Encoding` lists. `ContentDecoding::advertised` takes the most
decoded bytes you'll accept, here 8 MiB. A larger body fails with
`ResponseBodyLimit`.

Phantom doesn't add `Accept-Encoding` for you. Where it sits among the
headers is part of what servers check, so you set it yourself or through a
[request template](request-templates.md#apply-a-captured-request-template).

## Check which codings were decoded

`ResponseInfo::decoded_content_codings` lists the codings Phantom removed,
in `Content-Encoding` order.

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

The response headers still show what the server sent. `Content-Encoding` is
unchanged, and `Content-Length` counts the compressed bytes.

## Limits

- Decoding is strict. An unknown coding, one you didn't list, or corrupt
  data fails the first body read with `ContentDecoding`. Browsers pass
  unknown codings through.
- Only the final response is decoded. Phantom drops the bodies of redirect
  responses along the way.
- A request template sends `Accept-Encoding: gzip, deflate` to an
  `http://` host name such as `http://example.com/`. After a redirect to
  one, a `br` or `zstd` response fails.
- Server-sent event streams must not be compressed, even with decoding on.

## Next

- [Request templates](request-templates.md#apply-a-captured-request-template):
  templates that set `Accept-Encoding` for you.
- [Defaults and limits](../reference/limits.md): every default.
