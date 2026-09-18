use http_body_util::BodyExt;
use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    time::timeout,
};

use super::{TestResult, bounded_peer_test, host, read_head, target};
use crate::{
    OrderedResponseHeaders,
    http1::{
        AbsoluteForm, Http1Error, Http1UpgradeOutcome, PreparedGet, RequestHeader, send_get,
        send_prepared_upgrade,
    },
};

#[tokio::test]
async fn forward_upgrade_serializes_exact_absolute_form_and_ordered_fields() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let prepared = PreparedGet::new_forward(
            AbsoluteForm::parse("http://example.test:8080/socket?encoding=json")?,
            vec![
                RequestHeader::new("Host", "example.test:8080"),
                RequestHeader::new("Connection", "Upgrade"),
                RequestHeader::new("Upgrade", "websocket"),
                RequestHeader::new("X-Order", "last"),
            ],
        )?;
        let transaction = tokio::spawn(send_prepared_upgrade(client, prepared));

        let request = read_head(&mut server).await?;
        assert_eq!(
            request,
            b"GET http://example.test:8080/socket?encoding=json HTTP/1.1\r\n\
              Host: example.test:8080\r\n\
              Connection: Upgrade\r\n\
              Upgrade: websocket\r\n\
              X-Order: last\r\n\r\n"
        );
        server
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
            .await?;
        assert!(matches!(
            transaction.await??,
            Http1UpgradeOutcome::Upgraded(_)
        ));
        Ok(())
    })
    .await
}

#[test]
fn forward_upgrade_rejects_mismatched_host_before_io() -> TestResult {
    let result = PreparedGet::new_forward(
        AbsoluteForm::parse("https://example.test/socket")?,
        vec![RequestHeader::new("Host", "other.test")],
    );
    assert!(matches!(
        result,
        Err(Http1Error::MismatchedHost { index: 0 })
    ));
    Ok(())
}

#[tokio::test]
async fn upgrade_retains_ordered_head_and_coalesced_protocol_bytes() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let prepared = PreparedGet::new(target()?, vec![host()])?;
        let transaction = tokio::spawn(send_prepared_upgrade(client, prepared));

        let request = read_head(&mut server).await?;
        assert_eq!(
            request,
            b"GET /resource?item=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"
        );
        server
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nX-MiXeD: yes\r\n\r\nprotocol-bytes",
            )
            .await?;

        let Http1UpgradeOutcome::Upgraded(response) = transaction.await?? else {
            return Err("101 response was not upgraded".into());
        };
        let ordered = response
            .extensions()
            .get::<OrderedResponseHeaders>()
            .ok_or("upgrade response omitted ordered fields")?;
        assert_eq!(
            ordered
                .iter()
                .map(|header| (header.name(), header.value()))
                .collect::<Vec<_>>(),
            [
                ("Upgrade", b"test".as_slice()),
                ("X-MiXeD", b"yes".as_slice()),
            ]
        );
        let mut stream = response.into_body();
        let mut bytes = [0_u8; 14];
        stream.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"protocol-bytes");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn non_switching_response_remains_streaming_http() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let prepared = PreparedGet::new(target()?, vec![host()])?;
        let transaction = tokio::spawn(send_prepared_upgrade(client, prepared));
        read_head(&mut server).await?;
        server
            .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 6\r\n\r\ndenied")
            .await?;

        let Http1UpgradeOutcome::Rejected(response) = transaction.await?? else {
            return Err("ordinary response was treated as upgraded".into());
        };
        assert_eq!(response.status(), 401);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "denied");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn ordinary_get_rejects_unsolicited_switching_response() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: unexpected\r\n\r\n")
                .await
        });

        let result = send_get(client, target()?, vec![host()]).await;
        assert!(matches!(result, Err(Http1Error::UnexpectedUpgrade)));
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancelling_pending_upgrade_closes_the_stream() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let prepared = PreparedGet::new(target()?, vec![host()])?;
        let transaction = tokio::spawn(send_prepared_upgrade(client, prepared));
        read_head(&mut server).await?;

        transaction.abort();
        let _ = transaction.await;
        let mut byte = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), server.read(&mut byte))
            .await
            .map_err(|_| "cancelled Upgrade driver did not close its stream")??;
        assert_eq!(read, 0);
        Ok(())
    })
    .await
}
