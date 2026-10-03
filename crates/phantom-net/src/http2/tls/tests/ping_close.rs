//! The Chromium recipe's close of a TLS connection whose PING went
//! unanswered: `GOAWAY`, then the TCP FIN with no TLS `close_notify`, as
//! Chrome 154.0.8037.97 closed one in the retained `ping-unanswered.txt`
//! capture.

use std::{io::ErrorKind, time::Duration};

use phantom_profile::chromium;
use tokio::io::AsyncReadExt;

use super::{
    Http2TlsConnector, OriginForm, TEST_AUTHORITY, TEST_SERVER_NAME, TestIdentity, TestResult,
    TestServerAlpn, accept_tls, bounded_tls_test, loopback_listener, read_raw_frame,
    write_raw_frame,
};
use crate::http2::Http2Error;

const SETTINGS: u8 = 0x4;
const GOAWAY: u8 = 0x7;

#[tokio::test]
async fn chromium_ping_timeout_close_sends_nothing_after_goaway() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_tls(listener, acceptor).await?;
            let mut preface = [0_u8; 24];
            stream.read_exact(&mut preface).await?;
            write_raw_frame(&mut stream, SETTINGS, 0, 0, &[]).await?;
            // Read the client's frames, its PING included, and answer none.
            let goaway = loop {
                let frame = read_raw_frame(&mut stream).await?;
                if frame.kind == GOAWAY {
                    break frame.payload;
                }
            };
            // The TLS records end with the GOAWAY's; read what the client
            // sends after it on the TCP stream itself.
            let mut after = Vec::new();
            match stream.get_mut().read_to_end(&mut after).await {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
            TestResult::Ok((goaway, after))
        });

        let mut http2 = chromium::v154_http2();
        http2.preface_ping_after = Some(Duration::from_millis(300));
        http2.ping_timeout = Some(Duration::from_secs(1));
        let connector = Http2TlsConnector::new_with_roots(
            &chromium::v154_tls(),
            &http2,
            [identity.root_der()],
        )?;
        let connection = connector
            .connect_direct("127.0.0.1", address.port(), TEST_SERVER_NAME)
            .await?;
        tokio::time::sleep(Duration::from_millis(600)).await;
        let result = connection
            .send_get(TEST_AUTHORITY, OriginForm::parse("/")?, Vec::new())
            .await;
        assert!(matches!(result, Err(Http2Error::PingTimeout)));

        let (goaway, after) = server.await??;
        assert_eq!(goaway.get(8..), Some(&b"Failed ping."[..]));
        assert!(after.is_empty(), "after GOAWAY: {after:02x?}");
        Ok(())
    })
    .await
}
