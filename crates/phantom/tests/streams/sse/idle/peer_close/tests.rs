use std::{io, sync::Arc};

use super::{CLIENT_BYTE, ReadFailure, ReadPeer, TestResult, finish_with_cleanup, original_fault};

#[tokio::test]
async fn actual_eof_closes_a_pending_idle_read() -> TestResult<()> {
    let mut peer = ReadPeer::new();
    let primary = async {
        peer.start(None).await?;
        peer.send_eof().await?;
        let result = peer.observe().await?;
        let state = peer.witness().await?;
        assert!(state.eof);
        assert_eq!(state.byte, None);
        assert_eq!(state.injected, None);
        result
    }
    .await;
    finish_with_cleanup(primary, peer.stop().await)
}

#[tokio::test]
async fn actual_client_byte_is_rejected_by_a_pending_idle_read() -> TestResult<()> {
    let mut peer = ReadPeer::new();
    let primary = async {
        peer.start(None).await?;
        peer.send_byte().await?;
        let result = peer.observe().await?;
        let state = peer.witness().await?;
        assert_eq!(state.byte, Some(CLIENT_BYTE));
        assert!(!state.eof);
        assert_eq!(state.injected, None);
        let error = result
            .err()
            .ok_or("idle close helper accepted client data")?;
        assert_eq!(
            error.to_string(),
            "idle response received unexpected client bytes"
        );
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, peer.stop().await)
}

#[tokio::test]
async fn supported_disconnect_errors_close_a_pending_idle_read() -> TestResult<()> {
    for kind in [
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::UnexpectedEof,
    ] {
        let identity = Arc::new(());
        let mut peer = ReadPeer::new();
        let primary = async {
            peer.start(Some(original_fault(kind, &identity))).await?;
            peer.send_byte().await?;
            let result = peer.observe().await?;
            let state = peer.witness().await?;
            assert_eq!(state.byte, Some(CLIENT_BYTE));
            assert!(!state.eof);
            assert_eq!(state.injected, Some(kind));
            result
        }
        .await;
        finish_with_cleanup(primary, peer.stop().await)?;
    }
    Ok(())
}

#[tokio::test]
async fn unrelated_read_failure_keeps_its_original_typed_cause() -> TestResult<()> {
    let identity = Arc::new(());
    let mut peer = ReadPeer::new();
    let primary = async {
        let fault = original_fault(io::ErrorKind::PermissionDenied, &identity);
        peer.start(Some(fault)).await?;
        peer.send_byte().await?;
        let result = peer.observe().await?;
        let state = peer.witness().await?;
        assert_eq!(state.byte, Some(CLIENT_BYTE));
        assert!(!state.eof);
        assert_eq!(state.injected, Some(io::ErrorKind::PermissionDenied));
        let error = result
            .err()
            .ok_or("idle close helper accepted unrelated read failure")?;
        let original = error
            .downcast_ref::<io::Error>()
            .ok_or("idle close helper discarded the original I/O error")?;
        assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
        let cause = original
            .get_ref()
            .and_then(|source| source.downcast_ref::<ReadFailure>())
            .ok_or("idle close helper discarded the typed read cause")?;
        assert!(Arc::ptr_eq(&cause.0, &identity));
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, peer.stop().await)
}
