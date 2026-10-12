use std::{error::Error, net::Ipv4Addr};

use tokio::{
    net::TcpListener,
    sync::Barrier,
    time::{Instant, timeout_at},
};

use crate::support::deadline::FixtureDeadline;

use super::{
    H2_ALPN, TEST_TIMEOUT, TestIdentity, TestResult, bounded, reuse_ownership, send,
    send_after_barrier, test_client,
};

pub(super) async fn cold() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = reuse_ownership::spawn_server(listener, acceptor, 2, None);

        let session = test_client(&identity, true)?;
        let start = std::sync::Arc::new(Barrier::new(3));
        let first = tokio::spawn(send_after_barrier(
            session.clone(),
            format!("https://{address}/first"),
            start.clone(),
        ));
        let second = tokio::spawn(send_after_barrier(
            session.clone(),
            format!("https://{address}/second"),
            start.clone(),
        ));
        start.wait().await;

        first.await??;
        second.await??;
        drop(session);

        let requests = server.await??;
        let mut stream_ids = requests
            .iter()
            .map(|(stream_id, _)| *stream_id)
            .collect::<Vec<_>>();
        stream_ids.sort_unstable();
        let mut paths = requests
            .into_iter()
            .map(|(_, path)| path)
            .collect::<Vec<_>>();
        paths.sort_unstable();
        assert_eq!(stream_ids, [1, 3]);
        assert_eq!(paths, vec!["/first".to_owned(), "/second".to_owned()]);
        Ok(())
    })
    .await
}

pub(super) async fn independent() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let (identity, address, server) = timeout_at(deadline, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = reuse_ownership::spawn_independent(listener, acceptor, None);
        Ok::<_, Box<dyn Error + Send + Sync>>((identity, address, server))
    })
    .await
    .map_err(|elapsed| FixtureDeadline::new("session test exceeded its deadline", elapsed))??;

    let caller = match timeout_at(deadline, async {
        let first_client = test_client(&identity, true)?;
        let second_client = test_client(&identity, true)?;
        let first = tokio::spawn(send(first_client, format!("https://{address}/first")));
        let second = tokio::spawn(send(second_client, format!("https://{address}/second")));

        first.await??;
        second.await??;
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(elapsed) => Err(FixtureDeadline::new("session test exceeded its deadline", elapsed).into()),
    };

    let mut connections = reuse_ownership::collect_independent(caller, server).await?;
    connections.sort_unstable();
    assert_eq!(
        connections,
        [
            vec![(1, "/first".to_owned())],
            vec![(1, "/second".to_owned())]
        ]
    );
    Ok(())
}
