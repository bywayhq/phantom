//! Opens a WebSocket over an HTTP/1.1 Upgrade, sends one text message, prints
//! the first message the server returns, and closes the connection.
//!
//! This mirrors "Open a WebSocket over HTTP/1.1" in `docs/guides/websocket.md`.
//! It needs the `websocket` feature and a `ws://` or `wss://` server, such as
//! an echo server:
//!
//! ```console
//! cargo run -p phantom-http --example websocket --features websocket -- wss://example.com/echo
//! ```
//!
//! The second argument is the text to send (default `hello`). A WebSocket
//! connect ignores the client's request timeouts, so the example bounds it
//! with `tokio::time::timeout`.

use std::{env, process, time::Duration};

use phantom::{
    Client, WebSocketMessage,
    profile::{ClientProfile, chromium},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let Some(url) = args.next() else {
        eprintln!("usage: websocket <ws-or-wss-url> [text]");
        process::exit(2);
    };
    let text = args.next().unwrap_or_else(|| "hello".to_owned());

    let profile = ClientProfile::new(chromium::v154_tls());
    let client = Client::builder(profile).build()?;

    let connect = client.websocket(&url)?.connect();
    let mut socket = tokio::time::timeout(CONNECT_TIMEOUT, connect).await??;
    println!("opened: {}", socket.handshake_response().status());

    socket.send(WebSocketMessage::Text(text)).await?;
    // Phantom answers Ping frames itself; skip control events until a message arrives.
    let reply = loop {
        match socket.receive().await? {
            WebSocketMessage::Ping(_) | WebSocketMessage::Pong(_) => {}
            other => break other,
        }
    };
    match reply {
        WebSocketMessage::Text(text) => println!("text: {text}"),
        WebSocketMessage::Close(_) => {
            println!("server closed the connection");
            return Ok(());
        }
        // `Debug` shows the kind and length, never the payload.
        other => println!("received: {other:?}"),
    }

    // Send Close, then read until the server's Close reply.
    socket.close(None).await?;
    while !matches!(socket.receive().await?, WebSocketMessage::Close(_)) {}
    println!("closed");
    Ok(())
}
