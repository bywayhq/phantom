//! Reads a JSON array of strings from an HTTP/2 endpoint with a 1 MiB limit.
//!
//! ```console
//! cargo run -p phantom-http --example json --features json -- <url>
//! ```
//!
//! Supply an endpoint returning JSON such as `["Ada", "Grace"]`. This example
//! rejects 4xx and 5xx statuses before reading the JSON body.

use std::{env, io};

use phantom::{Client, HttpProtocol, RequestHeader, profile::browser::chrome};

const BODY_LIMIT: usize = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "usage: json <url>"))?;
    let client = Client::builder(chrome::v154_windows()).build()?;
    let response = client
        .get_with_protocol(HttpProtocol::Http2, &url)?
        .header(RequestHeader::new("accept", "application/json"))
        .send()
        .await?;
    let response = phantom::error_for_status(response)?;
    let response = phantom::response_json::<Vec<String>>(response, BODY_LIMIT).await?;

    println!("status: {}", response.status());
    for name in response.body() {
        println!("{name}");
    }
    Ok(())
}
