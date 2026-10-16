//! Completed SOCKS siblings survive H2 selection before their own TLS starts.
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
};

use btls::ssl::Ssl;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_btls::SslStream;

use super::*;

#[tokio::test]
async fn negotiated_h2_retains_a_completed_socks_sibling_through_real_tls_and_h2() -> TestResult<()>
{
    completed_h2(false).await
}

#[tokio::test]
async fn exact_h2_retains_a_completed_socks_sibling_through_real_tls_and_h2() -> TestResult<()> {
    completed_h2(true).await
}

async fn completed_h2(exact: bool) -> TestResult<()> {
    timeout(WAIT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let connectors = Connectors::new(&identity, true)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let family = AddressFamilyMemory::new();
        let (hello, hello_seen) = oneshot::channel();
        let (complete, complete_allowed) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let (claim, claimed) = oneshot::channel();
        let (quiet, was_quiet) = oneshot::channel();
        let peer = async {
            let mut spare = negotiate(&listener, false).await?;
            let mut winner = negotiate(&listener, false).await?;
            reply(&mut winner).await?;
            // Read the record and handshake type, then replay these bytes into TLS.
            // This fences the winner's completed SOCKS record before any TLS reply.
            let mut prefix = [0; 6];
            winner.read_exact(&mut prefix).await?;
            assert_eq!(prefix[0], 22, "winner did not begin a TLS handshake");
            assert_eq!(prefix[5], 1, "winner did not send ClientHello");
            hello.send(()).map_err(|_| "caller ended before ClientHello")?;
            complete_allowed.await?;
            reply(&mut spare).await?;
            let mut byte = [0];
            tokio::select! {
                biased;
                read = spare.read(&mut byte) => return Err(format!("unclaimed SOCKS spare sent TLS/application bytes: {read:?}").into()),
                ready = released => ready?,
            }
            let mut winner = SslStream::new(Ssl::new(acceptor.context())?, HelloPrefix {
                prefix, offset: 0, inner: winner,
            })?;
            Pin::new(&mut winner).accept().await?;
            tokio::select! {
                biased;
                read = spare.read(&mut byte) => return Err(format!("unclaimed H2 spare sent TLS/application bytes: {read:?}").into()),
                ready = claimed => ready?,
            }
            // Do not poll the retained TLS setup until this quiet check has run.
            quiet.send(()).map_err(|_| "caller ended before quiet acknowledgement")?;
            let spare = tls(spare, &acceptor).await?;
            let unused_winner = async {
                let mut winner = ::http2::server::handshake(winner).await?;
                if let Some(request) = winner.accept().await {
                    request?;
                    return Err("unused winner received an application request".into());
                }
                TestResult::Ok(())
            };
            tokio::try_join!(serve_h2(spare, "/completed"), unused_winner)?;
            let mut context = Context::from_waker(std::task::Waker::noop());
            assert!(listener.poll_accept(&mut context).is_pending(), "retained H2 redialed the proxy");
            TestResult::Ok(())
        };
        let caller = async {
            let opening = connectors.connect(exact, origin(&host, address.port(), false), &family);
            let mut opening = std::pin::pin!(opening);
            tokio::select! {
                result = &mut opening => {
                    result?;
                    return Err("H2 opening completed before its gated TLS handshake".into());
                }
                ready = hello_seen => ready?,
            }
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            // Scheduler plans are fixed before ClientHello. Clear only this local
            // observer: re-recording while winner TLS is held proves that the
            // other complete SOCKS negotiation ran, without sleeps or a new seam.
            assert!(family.forget_if_unchanged(&family.snapshot()));
            assert_eq!(family.family(), None);
            complete.send(()).map_err(|_| "peer ended before SOCKS completion")?;
            poll_fn(|cx| {
                if let Poll::Ready(result) = opening.as_mut().poll(cx) {
                    return Poll::Ready(result.and_then(|_| Err("winner escaped its TLS gate".into())));
                }
                if family.family() == Some(AddressFamily::Ipv4) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }).await?;
            release.send(()).map_err(|_| "peer ended before winner release")?;
            let (winner, slower) = opening.await?;
            assert!(matches!(winner, Http1Or2Connection::Http2(_)));
            let slower = slower.ok_or("completed SOCKS sibling was dropped by H2 selection")?;
            assert!(slower.progress().has_connected());
            claim.send(()).map_err(|_| "peer ended before claim")?;
            was_quiet.await?;
            let spare = slower.finish().await.ok_or("retained SOCKS TLS/H2 failed")?;
            assert!(matches!(spare, Http1Or2Connection::Http2(_)));
            send(&spare, "/completed").await?;
            drop(spare);
            drop(winner);
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    }).await?
}

struct HelloPrefix {
    prefix: [u8; 6],
    offset: usize,
    inner: TcpStream,
}

impl AsyncRead for HelloPrefix {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let count = (self.prefix.len() - self.offset).min(buffer.remaining());
            let start = self.offset;
            buffer.put_slice(&self.prefix[start..start + count]);
            self.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for HelloPrefix {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
