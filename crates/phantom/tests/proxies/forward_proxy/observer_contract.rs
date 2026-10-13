use std::{
    io,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{TestResult, answer_no_content, read_head};
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

const DEADLINE: Duration = Duration::from_secs(5);
const REQUEST: &[u8] = b"GET http://origin.test/observed HTTP/1.1\r\nHost: origin.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

async fn exchange(poison: bool) -> TestResult<(io::Result<Vec<u8>>, io::Result<()>, usize)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let heads = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&heads);
    let peer = ConnectionPeer::spawn(async move {
        let (stream, _) = listener.accept().await?;
        answer_no_content(stream, 4, heads).await
    });

    let operation = async {
        let mut client = TcpStream::connect(address).await?;
        client.write_all(REQUEST).await?;
        let first = timeout(DEADLINE, read_head(&mut client)).await??;
        assert_eq!(first, RESPONSE);

        if poison {
            let heads = Arc::clone(&observed);
            let poisoned = std::thread::spawn(move || {
                let _guard = heads
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                panic!("intentional forward observation lock poisoning");
            })
            .join();
            assert!(poisoned.is_err());
        }

        client.write_all(REQUEST).await?;
        let second = timeout(DEADLINE, read_head(&mut client)).await?;
        client.shutdown().await?;
        drop(client);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(second)
    }
    .await;

    let joined: TestResult<io::Result<()>> = async { Ok(timeout(DEADLINE, peer).await??) }.await;
    let (second, completed) = match (operation, joined) {
        (Ok(second), Ok(completed)) => (second, completed),
        (Err(error), Ok(completed)) => {
            return finish_with_cleanup(Err(error), completed.map_err(Into::into));
        }
        (Err(primary), Err(cleanup)) => return finish_with_cleanup(Err(primary), Err(cleanup)),
        (Ok(_), Err(error)) => return Err(error),
    };
    let count = observed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    Ok((second, completed, count))
}

#[tokio::test]
async fn a_poisoned_observer_is_a_failure_before_an_unrecorded_response() -> TestResult<()> {
    let (response, completed, count) = exchange(true).await?;
    assert_eq!(count, 1);
    assert!(
        matches!(response, Err(ref error) if crate::support::tls::is_peer_gone(error)),
        "proxy sent a response without recording its request: {response:?}"
    );
    let error = completed
        .err()
        .ok_or("poisoned observer completed successfully")?;
    assert_eq!(error.kind(), io::ErrorKind::Other);
    Ok(())
}

#[tokio::test]
async fn a_healthy_observer_records_both_literal_requests() -> TestResult<()> {
    let (response, completed, count) = exchange(false).await?;
    assert_eq!(response?, RESPONSE);
    assert_eq!(count, 2);
    assert!(
        completed.is_ok()
            || matches!(completed, Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}
