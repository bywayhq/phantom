use std::net::Ipv4Addr;

use phantom::{HttpProtocol, SessionTicketErrorKind};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use super::*;
use crate::support::{
    tls::{H1_ALPN, accept_tls_stream, read_head},
    tunnel_proxy::finish_with_cleanup,
};

#[tokio::test]
async fn portable_tickets_require_the_same_canonical_origin_and_proxy_pins() -> TestResult<()> {
    timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let valid = pins(&identity)?;
        let source = builder(&identity).server_spki_pins(valid.clone()).build()?;
        let canonical = builder(&identity)
            .server_spki_pins(ServerSpkiPins::new(vec![
                valid.sha256_digests()[0],
                valid.sha256_digests()[0],
            ])?)
            .build()?;
        let peer = async {
            for resumed in [false, true] {
                let (socket, _) = listener.accept().await?;
                let mut socket = accept_tls_stream(socket, acceptor.clone()).await?;
                assert_eq!(socket.ssl().session_reused(), resumed);
                read_head(&mut socket).await?;
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                socket.flush().await?;
            }
            TestResult::Ok(())
        };
        let caller = async {
            let url = format!("https://{address}/");
            source
                .get(HttpProtocol::Http1, &url)?
                .send()
                .await?
                .into_body()
                .collect_with_limit(0)
                .await?;
            let key = [7; 32];
            let snapshot = source.export_session_tickets(&key)?;
            for incompatible in [
                builder(&identity).build()?,
                builder(&identity)
                    .server_spki_pins(ServerSpkiPins::new(vec![[0; 32]])?)
                    .build()?,
                builder(&identity)
                    .server_spki_pins(valid.clone())
                    .proxy_server_spki_pins(valid)
                    .build()?,
            ] {
                let error = incompatible
                    .import_session_tickets(&snapshot, &key, &[])
                    .err()
                    .ok_or("incompatible pin policy imported a ticket")?;
                assert_eq!(error.kind(), SessionTicketErrorKind::Policy);
            }
            canonical.import_session_tickets(&snapshot, &key, &[])?;
            canonical
                .get(HttpProtocol::Http1, &url)?
                .send()
                .await?
                .into_body()
                .collect_with_limit(0)
                .await?;
            TestResult::Ok(())
        };
        let (caller, peer) = tokio::join!(caller, peer);
        finish_with_cleanup(caller, peer)
    })
    .await?
}
