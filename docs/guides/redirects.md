# Redirects

Have Phantom follow redirects for you, and see how each redirect changes the
method, the body and the headers.

> Read [Using the client](client.md) first.

## Follow redirects

Follow up to five redirects and see which URL gave the final response.

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

Without a redirect policy, Phantom returns redirect responses to you.

With one, it follows 301, 302, 303, 307 and 308 responses that have a
`Location` header. It moves between `http://` and `https://` in either
direction.

Each redirect changes the request like this:

- 301 and 302 turn a POST into a GET and drop the body.
- 303 turns every method except GET and HEAD into a GET and drops the body.
- 307 and 308 keep the method and send the body again.
- A redirect to another origin drops `Authorization`, `Cookie` and
  `Proxy-Authorization`, for that hop and every later one. Moving from
  `http://` to `https://` on the same host counts as another origin.

Every redirect uses the request's protocol and route. An exact HTTP/2
request redirected to an `http://` URL fails, because Phantom sends HTTP/2
only over TLS. Phantom doesn't switch protocols to follow it.

## Send a streaming body again

Keep a copy of a streaming body as it goes out, so a 307 or 308 redirect or
a retry can send it again.

Use `RequestBuilder::buffered_streaming_body(body, maximum_bytes)` in place
of `streaming_body`. The body streams as before, so the first attempt isn't
delayed. Phantom keeps up to `maximum_bytes` of it and frees the copy once
`send` returns. `buffered_streaming_body_with_trailers` keeps the trailers
too.

If the body grows past `maximum_bytes`, Phantom drops the copy. The current
attempt still sends the whole body, but a redirect or retry after it fails.

## Limits

- Running out of redirects is an error. Phantom doesn't return the last
  redirect response.
- A `Location` that isn't `http://` or `https://` is an error too.
- A redirect policy applies to the whole client. A single request can't
  change it.

## Next

- [Cookies](cookies.md): what the cookie jar sends on each redirect.
- [Retries and replays](retries.md): the retry budget redirects share.
- [Troubleshooting](troubleshooting.md#a-request-or-redirect-is-rejected):
  redirect errors and their fixes.
