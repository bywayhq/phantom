//! Sends Firefox 157 HTTP/3 requests on fresh connections to a loopback server.
//!
//! Pair it with `scripts/conformance/aioquic_versions.py`, which reports the
//! QUIC version, resumption and early-data acceptance for each connection.
//! After each request, the client waits for a ticket available to a later
//! connection. That ticket can come from any earlier connection kept open by
//! this run.
//!
//! Usage: `quic_version_interop <port> <root-der> [<requests>]`

use std::{env, error::Error, fs, num::NonZeroUsize, time::Duration};

use http_body_util::BodyExt as _;
use phantom_net::{http3::Http3Connector, request::OriginForm};
use phantom_profile::browser::firefox;
use tokio::time::{sleep, timeout};

const SERVER_NAME: &str = "localhost";
const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let usage = "usage: quic_version_interop <port> <root-der> [<requests>]";
    let mut args = env::args().skip(1);
    let port: u16 = args.next().ok_or(usage)?.parse()?;
    let root_path = args.next().ok_or(usage)?;
    let requests = request_count(args.next().as_deref())
        .map_err(|error| format!("requests must be a positive integer: {error}"))?;

    let root = fs::read(root_path)?;

    let connector = Http3Connector::new_with_additional_roots(
        &firefox::v157_quic_tls(),
        &firefox::v157_quic(),
        &firefox::v157_http3(),
        &firefox::v157_http3_request(),
        std::iter::once(root.as_slice()),
    )?
    .with_isolated_session_cache();
    let authority = format!("{SERVER_NAME}:{port}");
    let mut open = Vec::new();
    for request in 0..requests.get() {
        let connection = timeout(
            TIMEOUT,
            connector.connect(
                phantom_net::route::DatagramRoute::Direct(phantom_net::route::Endpoint {
                    host: "127.0.0.1",
                    port,
                }),
                SERVER_NAME,
            ),
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
        // Wait until the cache has a ticket to offer on a later connection.
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

fn request_count(value: Option<&str>) -> Result<NonZeroUsize, std::num::ParseIntError> {
    value.unwrap_or("3").parse()
}

#[cfg(test)]
mod tests {
    use super::request_count;

    #[test]
    fn default_and_positive_counts_preserve_the_number_of_observations() {
        for (value, expected) in [(None, 3), (Some("1"), 1), (Some("7"), 7)] {
            assert_eq!(request_count(value).unwrap().get(), expected);
        }
    }

    #[test]
    fn invalid_counts_cannot_produce_an_empty_successful_report() {
        for value in ["0", "-1", "invalid", "", "18446744073709551616"] {
            assert!(request_count(Some(value)).is_err(), "{value}");
        }
    }
}
