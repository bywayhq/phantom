//! Reads a server-sent event stream the way a browser's `EventSource` does,
//! reconnecting with `Last-Event-ID` after a disconnect, and prints each event.
//!
//! This mirrors "Reconnect with Last-Event-ID" in `docs/guides/sse.md`. It
//! needs the `sse` feature and a server that sends `text/event-stream`:
//!
//! ```console
//! cargo run -p phantom-http --example sse --features sse -- https://example.com/events h2
//! ```
//!
//! The second argument selects the exact protocol, `h1` or `h2` (default).
//! Use `h1` for a plaintext `http://` server. The example stops when the
//! server ends the stream with `204` or the reconnect budget runs out.

use std::{env, process, time::Duration};

use phantom::{
    Client, HttpProtocol,
    profile::{ClientProfile, chromium},
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let Some(url) = args.next() else {
        usage();
    };
    let protocol = match args.next().as_deref() {
        None | Some("h2") => HttpProtocol::Http2,
        Some("h1") => HttpProtocol::Http1,
        Some(_) => usage(),
    };

    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;

    let response = client
        .event_source(protocol, &url)?
        .initial_retry(Duration::from_secs(3))
        .max_reconnects(4)
        .connect()
        .await?;
    println!("connected: {}", response.status());
    let mut events = response.into_body();

    while let Some(event) = events.next_event().await? {
        println!("[{}] id={:?} {}", event.event(), event.id(), event.data());
    }
    println!("stream ended");
    Ok(())
}

fn usage() -> ! {
    eprintln!("usage: sse <event-stream-url> [h1|h2]");
    process::exit(2);
}
