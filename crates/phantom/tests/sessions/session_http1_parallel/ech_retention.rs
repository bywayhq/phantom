//! Windows' refused IPv6 connect leaves a genuine slower IPv4 attempt.
//! The custom profile combines Firefox's address policy with real ECH.

use std::{io, net::Ipv6Addr};

use phantom::{
    AddressResolver,
    dns::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup, HttpsRecordResolver},
};
use phantom_testkit::tls::{TEST_ECH_KEYS, ech_config, ech_config_list};
use tokio::{io::AsyncReadExt, net::TcpSocket, sync::watch};

use super::*;
use crate::support::ech::{
    ORIGIN_NAME, PUBLIC_NAME, Replayed, ech_acceptor, ech_tls_settings, handshake,
    https_rdata_with_alpn, origin_identity,
};

fn client(identity: &TestIdentity, port: u16) -> TestResult<Client> {
    let config = ech_config_list(&[ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME)]);
    let record = HttpsRecord::from_rdata(&https_rdata_with_alpn(&[b"http/1.1"], &config))?;
    let records = HttpsRecordLookup::new(
        vec![HttpsRecordAnswer::new(
            format!("_{port}._https.{ORIGIN_NAME}"),
            300,
            record,
        )],
        None,
    );
    let (published, ready) = watch::channel(false);
    let https = HttpsRecordResolver::from_fn(move |_, _| {
        let published = published.clone();
        let records = records.clone();
        async move {
            published.send_replace(true);
            Ok(records)
        }
    });
    // On this current-thread test runtime the HTTPS resolver returns and its
    // cache publishes without another await before address resolution resumes.
    // No sleep or network DNS response needs to fit the ECH lookup deadline.
    let addresses = AddressResolver::from_fn(move |_| {
        let mut ready = ready.clone();
        async move {
            while !*ready.borrow_and_update() {
                ready
                    .changed()
                    .await
                    .map_err(|_| io::Error::other("HTTPS result publisher ended"))?;
            }
            Ok(vec![Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()])
        }
    });
    let profile = ClientProfile::new(ech_tls_settings())
        .with_http1(firefox::v157_http1())
        .with_http2(firefox::v157_http2())
        .with_tcp(firefox::v157_tcp())
        .with_http3(crate::support::h3::client_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN.saturating_add(7))
        .https_record_discovery(https)
        .dns_resolver(addresses)
        .build()?)
}

async fn authenticated(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<Replayed>> {
    let (tcp, _) = listener.accept().await?;
    let (observed, stream) = handshake(tcp, acceptor).await?;
    assert_eq!(observed.outer_server_name.as_deref(), Some(PUBLIC_NAME));
    assert!(observed.ech_accepted);
    assert_eq!(observed.inner_server_name.as_deref(), Some(ORIGIN_NAME));
    Ok(stream)
}

async fn answer(stream: &mut SslStream<Replayed>, path: &str, complete_body: bool) -> TestResult {
    assert_eq!(request_path(&read_head(stream).await?), path);
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
        .await?;
    if complete_body {
        stream.write_all(b"done").await?;
    }
    Ok(())
}

async fn request(
    client: &Client,
    uri: &str,
    negotiated: bool,
) -> TestResult<http::Response<ResponseBody>> {
    let builder = if negotiated {
        client.get_negotiated(uri)?
    } else {
        client.get(HttpProtocol::Http1, uri)?
    };
    Ok(builder.send().await?)
}

async fn control(negotiated: bool) -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        // Bound but unlistened ::1 remains pending past the 250 ms IPv4
        // backup on Windows. This is a real TCP race, not a scripted attempt.
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
        let acceptor = ech_acceptor(&identity, H1_ALPN, 1, &TEST_ECH_KEYS[0])?;
        let client = client(&identity, port)?;
        let uri = |path| format!("https://{ORIGIN_NAME}:{port}/{path}");
        let first_uri = uri("first");
        let (first, mut winner) =
            tokio::try_join!(request(&client, &first_uri, negotiated), async {
                let mut stream = authenticated(&listener, &acceptor).await?;
                // Withhold the body so the winning connection stays leased.
                answer(&mut stream, "first", false).await?;
                TestResult::<_>::Ok(stream)
            },)?;

        // The pool must finish ECH on the losing attempt without sending an
        // HTTP request. Keep the winner leased throughout the spare's reuse.
        let mut spare = authenticated(&listener, &acceptor).await?;
        let mut byte = [0_u8; 1];
        assert!(
            timeout(QUIET_WINDOW, spare.read(&mut byte)).await.is_err(),
            "the authenticated spare sent application bytes or closed before a request"
        );

        let second_uri = uri("second");
        let (second, ()) = tokio::try_join!(
            request(&client, &second_uri, negotiated),
            answer(&mut spare, "second", true),
        )?;
        finish(second).await?;
        let third_uri = uri("third");
        let (third, ()) = tokio::try_join!(
            request(&client, &third_uri, negotiated),
            answer(&mut spare, "third", true),
        )?;
        finish(third).await?;
        assert!(
            timeout(QUIET_WINDOW, listener.accept()).await.is_err(),
            "a later request opened a third connection instead of reusing the spare"
        );
        winner.write_all(b"done").await?;
        finish(first).await?;
        drop(client);
        drop(spare);
        drop(winner);
        drop(unlistened);
        // No fixture task is spawned: cancellation and assertion unwinding
        // drop every peer socket and in-flight peer future in this scope.
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_adopts_an_authenticated_ech_backup_without_sending_a_request_until_claimed()
-> TestResult {
    for negotiated in [false, true] {
        control(negotiated).await?;
    }
    Ok(())
}
