use std::{
    io::IoSlice,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Wake, Waker},
    time::Duration,
};

use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{KeepalivePhase, TcpKeepaliveControl, TestResult, firefox_schedule, loopback_pair};
use crate::tcp::ProfileTcpStream;

struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn http2_retires_stream_tracking_after_disabling_the_socket() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, mut peer) = loopback_pair().await?;
        let control = TcpKeepaliveControl::opened(firefox_schedule()?, Duration::ZERO);
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        assert_eq!(control.apply(&socket, &waker)?, KeepalivePhase::ShortLived);
        assert!(SockRef::from(&socket).keepalive()?);
        assert!(control.lock().deadline.is_some());

        control.http2_negotiated();
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert!(control.lock().deadline.is_none());
        // Reporting H2 wakes I/O; it does not prematurely skip the socket update.
        assert!(SockRef::from(&socket).keepalive()?);
        let mut stream = ProfileTcpStream {
            stream: socket,
            keepalive: Some(control.clone()),
        };
        stream.write_all(b"request").await?;
        let mut request = [0; 7];
        peer.read_exact(&mut request).await?;
        assert_eq!(&request, b"request");
        assert!(stream.keepalive.is_none());
        assert!(!SockRef::from(stream.tcp_stream()).keepalive()?);
        {
            let state = control.lock();
            assert!(state.deadline.is_none());
            assert!(state.waker.is_none());
        }

        control.connection_idle();
        control.request_dispatched();
        control.upgraded();
        control.http2_negotiated();
        assert_eq!(
            control.apply(stream.tcp_stream(), &waker)?,
            KeepalivePhase::Disabled
        );
        assert!(control.lock().waker.is_none());
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert_eq!(
            control.applied_phases(),
            [KeepalivePhase::ShortLived, KeepalivePhase::Disabled]
        );

        peer.write_all(b"response").await?;
        let mut response = [0; 8];
        stream.read_exact(&mut response).await?;
        assert_eq!(&response, b"response");
        let buffers = [IoSlice::new(b"ab"), IoSlice::new(b"cd")];
        let written = stream.write_vectored(&buffers).await?;
        assert!(written > 0);
        let expected = b"abcd".get(..written).ok_or("oversized vectored write")?;
        let mut received = vec![0; written];
        peer.read_exact(&mut received).await?;
        assert_eq!(received, expected);
        assert!(stream.keepalive.is_none());
        assert!(!SockRef::from(stream.tcp_stream()).keepalive()?);
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn http2_before_first_io_never_enables_keepalive() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, mut peer) = loopback_pair().await?;
        let control = TcpKeepaliveControl::opened(firefox_schedule()?, Duration::ZERO);
        control.http2_negotiated();
        let mut stream = ProfileTcpStream {
            stream: socket,
            keepalive: Some(control.clone()),
        };

        stream.write_all(b"h2").await?;
        let mut received = [0; 2];
        peer.read_exact(&mut received).await?;
        assert_eq!(&received, b"h2");
        assert!(!SockRef::from(stream.tcp_stream()).keepalive()?);
        assert!(stream.keepalive.is_none());
        assert_eq!(control.applied_phases(), [KeepalivePhase::Disabled]);
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn an_idle_http1_stream_keeps_tracking_for_its_first_dispatch() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, mut peer) = loopback_pair().await?;
        let control = TcpKeepaliveControl::opened_idle(firefox_schedule()?, Duration::ZERO);
        let mut stream = ProfileTcpStream {
            stream: socket,
            keepalive: Some(control.clone()),
        };

        stream.write_all(b"idle").await?;
        assert!(!SockRef::from(stream.tcp_stream()).keepalive()?);
        assert!(stream.keepalive.is_some());
        assert!(control.applied_phases().is_empty());
        control.request_dispatched();
        stream.write_all(b"active").await?;
        let mut received = [0; 10];
        peer.read_exact(&mut received).await?;
        assert_eq!(&received, b"idleactive");
        assert!(SockRef::from(stream.tcp_stream()).keepalive()?);
        assert!(stream.keepalive.is_some());
        assert_eq!(control.applied_phases(), [KeepalivePhase::ShortLived]);
        Ok(())
    })
    .await?
}
