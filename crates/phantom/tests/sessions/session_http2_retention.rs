//! A real Windows TCP backup connects while the winner's TLS is held.
//! The connected loser authenticates and starts H2 without a request.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    time::Duration,
};

use btls::ssl::SslAcceptor;
use http_body_util::BodyExt as _;
use phantom::{
    AddressResolver, Client, HttpProtocol,
    dns::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup, HttpsRecordResolver},
    profile::{ClientProfile, browser::firefox},
};
use phantom_testkit::tls::{TEST_ECH_KEYS, ech_config, ech_config_list};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::watch,
    time::timeout,
};
use tokio_btls::SslStream;

use crate::support::{
    ech::{
        ORIGIN_NAME, PUBLIC_NAME, Replayed, ech_acceptor, ech_tls_settings, handshake,
        https_rdata_with_alpn, origin_identity,
    },
    h2::{accept_client_preface, read_frame, read_request_headers, write_frame},
    tls::{H2_ALPN, TestIdentity, tls_settings},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(100);

fn client(identity: &TestIdentity, port: u16, ech: bool) -> TestResult<Client> {
    let (published, ready) = watch::channel(!ech);
    let config = ech_config_list(&[ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME)]);
    let record = HttpsRecord::from_rdata(&https_rdata_with_alpn(&[b"h2"], &config))?;
    let records = HttpsRecordLookup::new(
        vec![HttpsRecordAnswer::new(
            format!("_{port}._https.{ORIGIN_NAME}"),
            300,
            record,
        )],
        None,
    );
    let https = HttpsRecordResolver::from_fn(move |_, _| {
        let published = published.clone();
        let records = records.clone();
        async move {
            published.send_replace(true);
            Ok(records)
        }
    });
    // The resolver finishes and its cache publishes on this current-thread
    // runtime before address resolution resumes, without a readiness sleep.
    let addresses = AddressResolver::from_fn(move |_| {
        let mut ready = ready.clone();
        async move {
            while !*ready.borrow_and_update() {
                ready
                    .changed()
                    .await
                    .map_err(|_| io::Error::other("HTTPS publisher ended"))?;
            }
            Ok(vec![Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()])
        }
    });
    let profile = ClientProfile::new(if ech {
        ech_tls_settings()
    } else {
        tls_settings()
    })
    .with_http1(firefox::v157_http1())
    .with_http2(firefox::v157_http2())
    .with_tcp(firefox::v157_tcp())
    .with_http3(crate::support::h3::client_settings());
    let mut builder = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .dns_resolver(addresses);
    if ech {
        builder = builder
            .alt_svc(NonZeroUsize::MIN.saturating_add(7))
            .https_record_discovery(https);
    }
    Ok(builder.build()?)
}

async fn authenticate(
    tcp: TcpStream,
    acceptor: &SslAcceptor,
    ech: bool,
) -> TestResult<SslStream<Replayed>> {
    // The replay wrapper also works without ECH and keeps one concrete peer type.
    let (observed, stream) = handshake(tcp, acceptor).await?;
    if ech {
        assert_eq!(observed.outer_server_name.as_deref(), Some(PUBLIC_NAME));
        assert!(observed.ech_accepted);
    } else {
        assert!(!observed.ech_accepted);
    }
    assert_eq!(observed.inner_server_name.as_deref(), Some(ORIGIN_NAME));
    Ok(stream)
}

async fn response(stream: &mut SslStream<Replayed>, id: u32) -> TestResult {
    read_request_headers(stream, id).await?;
    write_frame(stream, 0x1, 0x5, id, &[0x88]).await?;
    stream.flush().await?;
    Ok(())
}

async fn request(client: &Client, uri: &str) -> TestResult {
    let response = client.get(HttpProtocol::Http2, uri)?.send().await?;
    assert_eq!(response.status(), 200);
    response.into_body().collect().await?;
    Ok(())
}

async fn observe_redundant_preface(stream: &mut SslStream<Replayed>) -> TestResult {
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await?;
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let settings = read_frame(stream).await?;
    assert_eq!(settings.kind, 0x4, "backup omitted initial SETTINGS");
    assert_eq!(settings.stream_id, 0);
    assert_eq!(settings.flags & 0x1, 0, "initial SETTINGS was an ACK");
    // A redundant connection closes immediately. Writing a server SETTINGS
    // acknowledgement would race that closure instead of observing it.
    Ok(())
}

async fn no_application_before_close(stream: &mut SslStream<Replayed>) -> TestResult {
    loop {
        let frame = read_frame(stream).await?;
        assert_ne!(frame.kind, 0x1, "redundant backup sent request HEADERS");
        if frame.kind == 0x7 {
            assert_eq!(frame.stream_id, 0);
            assert!(frame.payload.len() >= 8);
            assert_eq!(&frame.payload[4..8], &0_u32.to_be_bytes());
            return Ok(());
        }
    }
}

async fn quiet_replacement(stream: &mut SslStream<Replayed>) -> TestResult {
    loop {
        let frame = read_frame(stream).await?;
        assert_ne!(frame.kind, 0x1, "backup sent an automatic request");
        assert_ne!(frame.kind, 0x7, "usable replacement was closed");
        if frame.kind == 0x4 && frame.flags & 1 != 0 {
            break;
        }
    }
    // Drain startup through our SETTINGS acknowledgement before timing a
    // cancel-safe one-byte read; never abandon a partially read frame.
    let mut byte = [0];
    assert!(
        timeout(QUIET, stream.read(&mut byte)).await.is_err(),
        "replacement sent bytes or closed before a request claimed it"
    );
    Ok(())
}

async fn control(ech: bool, retire_winner: bool) -> TestResult {
    timeout(DEADLINE, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        // Refused IPv6 remains in flight beyond the IPv4 backup on Windows.
        // Holding winner TLS lets it fail and advance to a second real IPv4 TCP.
        let unlistened = TcpSocket::new_v6()?;
        match unlistened.bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                eprintln!("skipped: this host has no IPv6 loopback address");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        let identity = origin_identity()?;
        let acceptor = if ech {
            ech_acceptor(&identity, H2_ALPN, 1, &TEST_ECH_KEYS[0])?
        } else {
            identity.acceptor(H2_ALPN)?
        };
        let client = client(&identity, port, ech)?;
        let uri = |path| format!("https://{ORIGIN_NAME}:{port}/{path}");
        let first = uri("first");
        let ((), (mut winner, spare_tcp)) = tokio::try_join!(request(&client, &first), async {
            let (first_tcp, _) = listener.accept().await?;
            let (spare_tcp, _) = listener.accept().await?;
            let mut winner = authenticate(first_tcp, &acceptor, ech).await?;
            accept_client_preface(&mut winner).await?;
            response(&mut winner, 3).await?;
            if retire_winner {
                let mut goaway = [0; 8];
                goaway[..4].copy_from_slice(&3_u32.to_be_bytes());
                write_frame(&mut winner, 0x7, 0, 0, &goaway).await?;
                winner.flush().await?;
            }
            TestResult::<_>::Ok((winner, spare_tcp))
        })?;
        let mut spare = authenticate(spare_tcp, &acceptor, ech).await?;
        if retire_winner {
            accept_client_preface(&mut spare).await?;
            quiet_replacement(&mut spare).await?;
            for (path, id) in [("second", 3), ("third", 5)] {
                let url = uri(path);
                tokio::try_join!(request(&client, &url), response(&mut spare, id))?;
            }
        } else {
            observe_redundant_preface(&mut spare).await?;
            no_application_before_close(&mut spare).await?;
            let second = uri("second");
            tokio::try_join!(request(&client, &second), response(&mut winner, 5))?;
        }
        assert!(
            timeout(QUIET, listener.accept()).await.is_err(),
            "request opened a third TCP connection"
        );
        drop(client);
        if retire_winner {
            no_application_before_close(&mut spare).await?;
        } else {
            no_application_before_close(&mut winner).await?;
        }
        // No fixture tasks: deadline/error/unwind drops both peers and pending
        // peer futures; the Client owns its protocol drivers and backup setup.
        drop(spare);
        drop(winner);
        drop(unlistened);
        Ok(())
    })
    .await
    .map_err(|_| "exact-H2 retention test exceeded its deadline")?
}

#[tokio::test]
async fn connected_h2_backups_authenticate_then_close_without_requests_when_redundant() -> TestResult
{
    for ech in [false, true] {
        control(ech, false).await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_connected_h2_backup_replaces_a_retired_winner_and_serves_later_requests() -> TestResult {
    for ech in [false, true] {
        control(ech, true).await?;
    }
    Ok(())
}
