//! Request failures retain logical origins without diagnostic URL fields.

use std::{net::Ipv4Addr, time::Duration};

use phantom::{
    Client, HttpProtocol, RedirectPolicy, RequestErrorKind, RequestHeader,
    RequestReplayObservation,
    profile::{ClientProfile, browser::chrome},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::support::tunnel_proxy::ConnectionPeer;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn client() -> Result<Client, phantom::BuildError> {
    Client::builder(ClientProfile::new(chrome::v154_tcp_tls()))
        .redirect_policy(RedirectPolicy::limited(std::num::NonZeroUsize::MIN))
        .build()
}

async fn head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == 16_384 {
            return Err(std::io::Error::other("request head exceeded test limit"));
        }

        bytes.push(stream.read_u8().await?);
    }
    Ok(bytes)
}

#[tokio::test]
async fn preflight_error_has_a_safe_origin_and_unparsed_input_has_none() -> TestResult {
    timeout(Duration::from_secs(10), async {
        let client = client()?;
        let Err(error) = client
            .get(
                HttpProtocol::Http1,
                "https://BÜCHER.Example/private?sentinel=value",
            )?
            .header(RequestHeader::new("Host", "forbidden"))
            .send()
            .await
        else {
            return Err("caller Host was accepted".into());
        };
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
        let origin = error.origin().ok_or("missing validated origin")?;
        assert_eq!(origin.scheme(), "https");
        assert_eq!(origin.host(), "xn--bcher-kva.example");
        assert_eq!(origin.port(), 443);
        assert_eq!(
            error.replay_observation(),
            RequestReplayObservation::Unknown
        );

        let formatted = format!("{error} {error:?}");
        for forbidden in ["private", "sentinel", "value", "forbidden"] {
            assert!(!formatted.contains(forbidden));
        }

        let Err(unparsed) = client.get(HttpProtocol::Http1, "http://user@example.test/") else {
            return Err("user information was accepted".into());
        };
        assert!(unparsed.origin().is_none());
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn failed_redirect_hop_reports_its_origin_and_setup_observation() -> TestResult {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let initial = listener.local_addr()?;
        let refused = phantom_testkit::tcp::ReservedPort::bind()?;
        let destination = refused.address();
        let peer = ConnectionPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let observed = head(&mut stream).await?;
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{destination}/private?sentinel=value\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await?;
            Ok::<_, std::io::Error>(observed)
        });
        let Err(error) = client()?
            .get(HttpProtocol::Http1, &format!("http://{initial}/start"))?
            .send()
            .await
        else {
            return Err("refused redirect target succeeded".into());
        };
        assert!(peer.await??.starts_with(b"GET /start HTTP/1.1\r\n"));
        let origin = error.origin().ok_or("missing redirected origin")?;
        assert_eq!(origin.scheme(), "http");
        assert_eq!(origin.host(), "127.0.0.1");
        assert_eq!(origin.port(), destination.port());
        assert_ne!(origin.port(), initial.port());
        assert_eq!(
            error.replay_observation(),
            RequestReplayObservation::ConnectionSetupFailure
        );

        let formatted = format!("{error} {error:?}");
        assert!(!formatted.contains("private"));
        assert!(!formatted.contains("sentinel"));
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn deferred_body_failure_and_collection_limit_keep_the_response_origin() -> TestResult {
    timeout(Duration::from_secs(10), async {
        for (wire, maximum, expected_kind) in [
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nab".as_slice(),
                4,
                RequestErrorKind::Http1,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc".as_slice(),
                2,
                RequestErrorKind::ResponseBodyLimit,
            ),
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let peer = ConnectionPeer::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let observed = head(&mut stream).await?;
                stream.write_all(wire).await?;
                stream.shutdown().await?;
                Ok::<_, std::io::Error>(observed)
            });
            let response = client()?
                .get(
                    HttpProtocol::Http1,
                    &format!("http://{address}/private?sentinel=value"),
                )?
                .send()
                .await?;
            assert_eq!(response.status(), phantom::StatusCode::OK);
            let Err(error) = response.into_body().collect_with_limit(maximum).await else {
                return Err("invalid body was accepted".into());
            };
            assert!(
                peer.await??
                    .starts_with(b"GET /private?sentinel=value HTTP/1.1\r\n")
            );
            assert_eq!(error.kind(), expected_kind);
            let origin = error.origin().ok_or("missing deferred error origin")?;
            assert_eq!(origin.scheme(), "http");
            assert_eq!(origin.host(), "127.0.0.1");
            assert_eq!(origin.port(), address.port());
            assert_eq!(
                error.replay_observation(),
                RequestReplayObservation::Unknown
            );

            let formatted = format!("{error} {error:?}");
            assert!(!formatted.contains("private"));
            assert!(!formatted.contains("sentinel"));
        }
        Ok(())
    })
    .await?
}
