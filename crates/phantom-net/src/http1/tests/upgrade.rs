use http_body_util::BodyExt;
use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    time::timeout,
};

use super::{TestResult, bounded_peer_test, host, read_head, target};
use crate::{
    OrderedResponseHeaders,
    http1::{Http1Error, Http1UpgradeOutcome, PreparedGet, send_get, send_prepared_upgrade},
};

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
