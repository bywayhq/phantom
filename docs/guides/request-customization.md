# Base URLs and header hooks

Use a base URL for relative request paths. Register header hooks to apply
the same caller headers across HTTP requests.

## Set a base URL and shared headers

```rust,no_run
use phantom::{Client, HttpProtocol, RequestHeader};
use phantom::profile::browser::chrome;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::builder(chrome::v154_windows())
    .base_url("https://api.example.com/v1/")?
    .header_hook(|request| {
        request.set(RequestHeader::new("x-app-version", "1"))
    })
    .build()?;

let response = client.get(HttpProtocol::Http2, "users")?
    .query_pairs([("page", "2")])?
    .send().await?;
# drop(response);
# Ok(())
# }
```

This sends a request to `https://api.example.com/v1/users?page=2`.

## Resolve relative paths

URL joining follows these rules:

| Base | Request | Result |
| --- | --- | --- |
| `https://example.com/api/` | `users` | `https://example.com/api/users` |
| `https://example.com/api` | `users` | `https://example.com/users` |
| `https://example.com/api/` | `/users` | `https://example.com/users` |
| `https://example.com/api/?old=1` | `?new=2` | `https://example.com/api/?new=2` |
| `https://example.com/api/` | `//other.example/users` | `https://other.example/users` |

An absolute URL overrides the base. It keeps its existing request-target
bytes. A base URL is a convenience, not a restriction to one origin.
WebSocket URLs still need to be absolute.

## Customize one request

Client hooks run in registration order, followed by request hooks. A later
hook sees earlier changes. `set` replaces a name at its first caller
position, `append` keeps duplicates, and `remove` removes every match.

```rust,no_run
use phantom::{Client, HttpProtocol, RequestHeader};

async fn fetch(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.get(HttpProtocol::Http2, "https://example.com/data")?
        .header_hook(|request| {
            request.set(RequestHeader::new("x-app-version", "2"))
        })
        .send().await?;
    drop(response);
    Ok(())
}
```

`without_header_hooks` skips client hooks and clears request hooks already
registered. Hooks you add afterward still run.

Hooks run once when sending begins, before network I/O. They see the initial
method, resolved URL, and caller headers. Templates, cookies, and client
hints are added afterward. Matching headers keep their template positions.

If a hook supplies credentials, check `request.uri()` in your callback.
Compare its scheme, host, and port before adding the credential. Absolute
URLs can override the base. Retries reuse the hook's result.

Hooks do not rerun on redirects. Cross-origin redirects remove
`Authorization`, `Cookie`, `Cookie2`, and `Proxy-Authorization`. Custom
credential fields, such as `x-api-key`, are not protected by this rule,
even when marked sensitive. Use `RedirectPolicy::none()` and check each
new request's origin yourself ([Follow redirects](redirects.md#follow-redirects)). A
signature for the initial URL is not regenerated for redirect URLs.

## Limits

- Hooks are synchronous and should not block.
- Invalid header edits and callback errors stop the request before I/O.
- SSE runs hooks on each underlying HTTP request, including reconnects.
  Hooks cannot edit its managed `Last-Event-ID`.
- WebSocket openings do not run these hooks.

## Next

- [Request templates](request-templates.md): browser header positions.
- [Request bodies](request-bodies.md): prepare JSON, forms, and multipart.
- [Redirects](redirects.md): methods, bodies, and credentials across hops.
