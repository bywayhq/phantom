//! Sends Firefox 156 HTTP/3 requests on fresh connections to a loopback server.
//!
//! Pair it with `scripts/conformance/aioquic_versions.py`, which reports the
//! QUIC version of each connection. The first connection starts in QUIC v1 and
//! follows the server to v2; later connections present the session ticket the
//! previous one received and so start in v2, with early data.
//!
//! Usage: `quic_version_interop <port> <root-der> [<requests>]`

use std::{env, error::Error, fs, time::Duration};

use http_body_util::BodyExt as _;
use phantom_net::http3::{Http3Connector, OriginForm};
use phantom_profile::firefox;
use tokio::time::{sleep, timeout};

const SERVER_NAME: &str = "localhost";
const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let usage = "usage: quic_version_interop <port> <root-der> [<requests>]";
    let mut args = env::args().skip(1);
    let port: u16 = args.next().ok_or(usage)?.parse()?;
    let root = fs::read(args.next().ok_or(usage)?)?;
    let requests: usize = args.next().map_or(Ok(3), |value| value.parse())?;

    let connector = Http3Connector::new_with_additional_roots(
        &firefox::v156_http3_tls(),
        &firefox::v156_quic(),
        &firefox::v156_http3(),
        &firefox::v156_http3_request(),
        std::iter::once(root.as_slice()),
    )?
    .with_isolated_session_cache();
    let authority = format!("{SERVER_NAME}:{port}");
    let mut open = Vec::new();
    for request in 0..requests {
        let connection = timeout(
            TIMEOUT,
            connector.connect_direct("127.0.0.1", port, SERVER_NAME),
        )
        .await??;
        let response = timeout(
            TIMEOUT,
            connector.send_get_on(&connection, &authority, OriginForm::parse("/")?, Vec::new()),
        )
        .await??;
        let status = response.status();
        let body = timeout(TIMEOUT, response.into_body().collect())
            .await??
            .to_bytes();
        println!(
            "request={request} status={} body={:?} resumed={}",
            status.as_u16(),
            String::from_utf8_lossy(&body),
            connection.session_resumed()
        );
        // The next connection resumes only once this one holds a ticket.
        let waited = timeout(TIMEOUT, async {
            while !connector.has_ticket_for(SERVER_NAME) {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if waited.is_err() {
            return Err("no session ticket arrived".into());
        }
        open.push(connection);
    }
    Ok(())
}
