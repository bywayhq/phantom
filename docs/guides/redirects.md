# Redirects

Follow redirects without leaving the request's route or protocol, and see
how each hop changes the method, the body, and the fields.

> For builders who have read [Using the client](client.md).

## Follow redirects

Follow a bounded number of redirects and see where the response came from.

```rust
use std::num::NonZeroUsize;

use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, RedirectPolicy, ResponseInfo};

async fn follow() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2());
    let client = Client::builder(profile)
        .redirect_policy(RedirectPolicy::limited(
            NonZeroUsize::new(5).expect("five is nonzero"),
        ))
        .build()?;

    let response = client.get(HttpProtocol::Http2, "https://example.com/old")?.send().await?;
    if let Some(info) = response.extensions().get::<ResponseInfo>() {
        println!("{} after {} redirects", info.effective_uri(), info.redirects_followed());
    }
    Ok(())
}
```

- `RedirectPolicy::none()`, the default, returns redirect responses to you.
- Only 301, 302, 303, 307, and 308 with a `Location` are followed, between
  `http://` and `https://` URLs in either direction. A redirect without
  `Location` is returned unchanged.
- 301 and 302 rewrite POST to GET, and 303 rewrites every method except GET
  and HEAD, dropping the body, static trailers, and body-describing fields.
  307 and 308 keep the method and resend an owned body.
- A cross-origin hop removes `Authorization`, `Cookie`, `Cookie2`, and
  `Proxy-Authorization` fields and trailers, yours and the request
  template's own, for that hop and every later one, and rebuilds client
  hints. A change between `http://` and `https://` on the same host is
  cross-origin.
  Every hop keeps the route and protocol rule, one total timeout, and one
  retry budget.

## Send a streaming body again

Keep a streaming body as it is sent, so a 307 or 308 redirect or a replay can
send it again.

- `RequestBuilder::buffered_streaming_body(body, maximum_bytes)` streams the
  body as `streaming_body` does and keeps up to `maximum_bytes` of its data as
  it goes, so the first attempt is not delayed;
  `buffered_streaming_body_with_trailers` keeps the trailer frame too.
- A redirect that keeps the method, the proxy-authentication and `Critical-CH`
  replays, and the reused-connection, unprocessed-request, PING-failure, and
  status replays in [Retries and replays](retries.md) send the kept frames
  with the same boundaries and then read on from the body.
- Each class keeps its own method rule, so the PING-failure resend of the
  Chromium recipes can send a buffered `POST` twice.
- Past the limit the kept frames are freed and the body is one-shot: the
  attempt in progress still sends all of it, and a later attempt fails with
  `RequestErrorKind::RequestBody` or returns the earlier failure. The limit
  counts data bytes; a kept frame holds the buffer its bytes come from.
- Once `send` returns, the kept frames are freed, at once or, while an
  attempt is still uploading, as it sends them.

## Limits

- Each hop is checked against the request's protocol and route before it is
  sent. A hop they cannot carry fails with that combination's error, for
  example `RequestErrorKind::UnsupportedScheme` for an exact H2 request
  redirected to `http://`. Phantom does not switch protocol or route to
  follow it.
- A redirect target that is not `http://` or `https://`, more than one
  `Location`, an invalid location, or running out of redirects fails with
  `RequestErrorKind::Redirect`; the redirect response is not returned. A 307
  or 308 with a one-shot streaming body, or a buffered one past its limit,
  fails with `RequestErrorKind::RequestBody`; a buffered one within its limit
  is sent again ([above](#send-a-streaming-body-again)).

## Next

- [Cookies](cookies.md): what the cookie jar sends on each hop.
- [Retries and replays](retries.md): the retry budget redirects share.
- [Troubleshooting](troubleshooting.md#a-request-or-redirect-is-rejected):
  redirect errors and their fixes.
