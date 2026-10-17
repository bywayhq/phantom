# Request timings

Inspect setup, response headers and body consumption for one request.

## Inspect request timings

Keep the diagnostics handle to inspect a request after headers or failure.

```no_run
use std::num::NonZeroUsize;
use phantom::{Client, HttpProtocol, RequestError};

async fn inspect(client: &Client) -> Result<(), RequestError> {
    let mut request = client.get(HttpProtocol::Http2, "https://example.com/")?;
    let diagnostics = request.diagnostics(NonZeroUsize::new(128).unwrap());
    let response = request.send().await?;
    println!("{:?}", diagnostics.snapshot());
    response.into_body().collect_with_limit(1 << 20).await?;
    println!("{:?}", diagnostics.snapshot());
    Ok(())
}
```

Body completion can follow response headers. See
[Request diagnostics](../reference/request-diagnostics.md) for event meanings
and missing phases.

## Next

- [Request diagnostics reference](../reference/request-diagnostics.md): event meanings and limits.
- [Troubleshooting](troubleshooting.md): common request failures.
