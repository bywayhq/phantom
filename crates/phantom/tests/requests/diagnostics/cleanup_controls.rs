use std::fs;

use super::{ScratchCleanupError, TestResult, remove_scratch_dir, scratch_dir};

#[tokio::test]
async fn dropping_a_scratch_owner_removes_its_closed_file_and_directory() -> TestResult<()> {
    let directory = scratch_dir("drop-control")?;
    let retained = directory.path().to_path_buf();
    fs::write(retained.join("observed"), b"actual fixture bytes")?;
    assert_eq!(
        fs::read(retained.join("observed"))?,
        b"actual fixture bytes"
    );
    drop(directory);

    let removed = !retained.exists();
    if retained.exists() {
        fs::remove_dir_all(&retained)?;
    }
    assert!(removed, "scratch owner abandoned its directory");
    Ok(())
}

#[tokio::test]
async fn scratch_removal_keeps_an_actual_filesystem_failure() -> TestResult<()> {
    let directory = scratch_dir("failure-control")?;
    let invalid = directory.path().join("ordinary-file");
    fs::write(&invalid, b"retained failure bytes")?;
    let reference = fs::remove_dir_all(&invalid)
        .err()
        .ok_or("file removal unexpectedly succeeded")?;

    let result = remove_scratch_dir(&invalid).await;
    let retained = fs::read(&invalid)?;
    directory.cleanup().await?;

    let error = result
        .err()
        .ok_or("scratch cleanup discarded its failure")?;
    assert_eq!(error.kind(), reference.kind());
    assert_eq!(error.raw_os_error(), reference.raw_os_error());
    assert_eq!(retained, b"retained failure bytes");
    Ok(())
}

#[tokio::test]
async fn explicit_scratch_cleanup_removes_a_real_nonempty_directory() -> TestResult<()> {
    let directory = scratch_dir("cleanup-control")?;
    let retained = directory.path().to_path_buf();
    fs::write(retained.join("observed"), b"positive fixture bytes")?;
    assert_eq!(
        fs::read(retained.join("observed"))?,
        b"positive fixture bytes"
    );

    directory.cleanup().await?;
    assert!(!retained.exists());
    Ok(())
}

#[tokio::test]
async fn explicit_cleanup_failure_reports_its_retained_path_and_original_error() -> TestResult<()> {
    let directory = scratch_dir("retained-control")?;
    let retained = directory.path().to_path_buf();
    fs::remove_dir(&retained)?;
    fs::write(&retained, b"retained ownership failure")?;
    let reference = fs::remove_dir_all(&retained)
        .err()
        .ok_or("file removal unexpectedly succeeded")?;

    let error: ScratchCleanupError = directory
        .cleanup()
        .await
        .err()
        .ok_or("cleanup failure was discarded")?;
    let bytes = fs::read(&retained)?;
    fs::remove_file(&retained)?;

    assert_eq!(error.retained_path, retained);
    assert_eq!(error.source.kind(), reference.kind());
    assert_eq!(error.source.raw_os_error(), reference.raw_os_error());
    assert_eq!(bytes, b"retained ownership failure");
    assert!(error.to_string().contains(&retained.display().to_string()));
    Ok(())
}

#[tokio::test]
async fn cancelling_a_fixture_future_drops_its_actual_scratch_owner() -> TestResult<()> {
    let directory = scratch_dir("cancel-control")?;
    let retained = directory.path().to_path_buf();
    fs::write(retained.join("observed"), b"cancelled fixture bytes")?;
    let (started, ready) = tokio::sync::oneshot::channel();
    let task = super::ConnectionPeer::spawn(async move {
        let owner = directory;
        assert_eq!(
            fs::read(owner.path().join("observed"))?,
            b"cancelled fixture bytes"
        );
        started
            .send(())
            .map_err(|()| "scratch control dropped readiness receiver")?;
        std::future::pending::<()>().await;
        TestResult::Ok(())
    });
    tokio::time::timeout(super::TEST_TIMEOUT, ready).await??;

    task.abort();
    let joined = tokio::time::timeout(super::TEST_TIMEOUT, task).await?;
    assert!(matches!(joined, Err(ref error) if error.is_cancelled()));
    assert!(!retained.exists());
    Ok(())
}
