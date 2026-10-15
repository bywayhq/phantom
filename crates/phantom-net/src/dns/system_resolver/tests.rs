use super::read_current_snapshot;
use std::{cell::Cell, io};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn a_known_old_snapshot_never_starts_the_reader() {
    let read = Cell::new(false);
    let result = read_current_snapshot(
        || Ok(false),
        || {
            read.set(true);
            Ok(())
        },
        |()| Ok(()),
    );
    assert!(result.is_err());
    assert!(!read.get());
}
#[test]
fn invalidation_during_native_read_never_prepares_or_publishes() {
    let current = Cell::new(true);
    let prepared = Cell::new(false);
    let result = read_current_snapshot(
        || Ok(current.get()),
        || {
            current.set(false);
            Ok(())
        },
        |()| {
            prepared.set(true);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!prepared.get());
}
#[test]
fn invalidation_during_projection_never_publishes() {
    let current = Cell::new(true);
    let result = read_current_snapshot(
        || Ok(current.get()),
        || Ok(()),
        |()| {
            current.set(false);
            Ok(17)
        },
    );
    assert!(result.is_err());
}
#[test]
fn terminal_watch_error_preserves_its_typed_source() {
    let result = read_current_snapshot(
        || {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic terminal watch",
            ))
        },
        || Ok(()),
        |()| Ok(()),
    );
    assert!(result.is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied));
}
#[test]
fn stable_generation_returns_one_fully_projected_snapshot() -> TestResult {
    let reads = Cell::new(0);
    let result = read_current_snapshot(
        || Ok(true),
        || {
            reads.set(reads.get() + 1);
            Ok(19)
        },
        |value| Ok(value + 1),
    )?;
    assert_eq!(result, 20);
    assert_eq!(reads.get(), 1);
    Ok(())
}

#[tokio::test]
async fn system_only_selects_os_before_any_phantom_socket_or_https_lookup() -> TestResult {
    use super::{ConfigurationFailure, Snapshot};
    use crate::dns::system_configuration::WindowsDnsIneligibility;
    crate::udp::observed::take();
    let snapshot = Snapshot::SystemOnly(WindowsDnsIneligibility {
        nrpt: true,
        ..Default::default()
    });
    let addresses = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        snapshot.resolve_address("localhost", None),
    )
    .await??;
    let (addresses, _) = addresses.into_parts();
    let addresses = addresses?;
    assert!(!addresses.is_empty());
    assert!(addresses.iter().all(|address| address.ip().is_loopback()));
    assert!(crate::udp::observed::take().is_empty());
    let error = snapshot
        .lookup(None)
        .err()
        .ok_or("SystemOnly HTTPS lookup was accepted")?;
    let typed = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ConfigurationFailure>())
        .ok_or("typed SystemOnly failure missing")?;
    assert!(matches!(typed, ConfigurationFailure::SystemOnly(reasons) if reasons.nrpt));
    Ok(())
}

fn generation_token(
    generation: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> crate::host_resolver::DnsConfigurationToken {
    use std::sync::atomic::Ordering;
    let expected = generation.load(Ordering::SeqCst);
    let generation = generation.clone();
    crate::host_resolver::DnsConfigurationToken::new(move || {
        Ok(generation.load(Ordering::SeqCst) == expected)
    })
}

fn snapshot() -> std::sync::Arc<super::Snapshot> {
    std::sync::Arc::new(super::Snapshot::SystemOnly(
        crate::dns::system_configuration::WindowsDnsIneligibility::default(),
    ))
}

#[tokio::test]
async fn same_generation_consumers_share_one_refresh_and_then_the_cached_snapshot() -> TestResult {
    use super::{SnapshotSelection, SnapshotState};
    use std::sync::{Arc, atomic::AtomicUsize};
    let generation = Arc::new(AtomicUsize::new(0));
    let token = generation_token(&generation);
    let mut state = SnapshotState::default();
    let SnapshotSelection::Start { receiver, reply } = state.select(&token)? else {
        return Err("first consumer did not start refresh".into());
    };
    let mut receivers = vec![receiver];
    // All consumers arrive before the worker dequeues its one request.
    for _ in 0..63 {
        match state.select(&token)? {
            SnapshotSelection::Waiting {
                receiver,
                same_generation: true,
            } => receivers.push(receiver),
            _ => {
                return Err(
                    "same generation queued another refresh or bypassed pending work".into(),
                );
            }
        }
    }
    let expected = snapshot();
    drop(reply.send_replace(Some(state.finish(&token, Ok(expected.clone())))));
    for mut receiver in receivers {
        let actual = completed_with_deadline(&mut receiver)
            .await?
            .map_err(io::Error::other)?;
        assert!(Arc::ptr_eq(&actual, &expected));
    }
    let SnapshotSelection::Cached(actual) = state.select(&token)? else {
        return Err("stable generation did not use snapshot fast path".into());
    };
    assert!(Arc::ptr_eq(&actual, &expected));
    assert!(state.pending.is_none());
    Ok(())
}

#[tokio::test]
async fn crossed_generation_waits_for_owned_work_and_cannot_publish_an_old_snapshot() -> TestResult
{
    use super::{SnapshotSelection, SnapshotState};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let generation = Arc::new(AtomicUsize::new(0));
    let old = generation_token(&generation);
    let mut state = SnapshotState::default();
    let SnapshotSelection::Start {
        receiver: mut original,
        reply,
    } = state.select(&old)?
    else {
        return Err("old consumer did not start refresh".into());
    };
    generation.store(1, Ordering::SeqCst);
    let current = generation_token(&generation);
    let SnapshotSelection::Waiting {
        receiver: mut next,
        same_generation: false,
    } = state.select(&current)?
    else {
        return Err("new generation bypassed owned refresh".into());
    };
    assert!(state.pending.is_some());
    drop(reply.send_replace(Some(state.finish(&old, Ok(snapshot())))));
    assert!(completed_with_deadline(&mut original).await?.is_err());
    assert!(completed_with_deadline(&mut next).await?.is_err());
    assert!(state.cached.is_none());
    assert!(state.select(&old).is_err());
    let SnapshotSelection::Start {
        receiver: mut new,
        reply,
    } = state.select(&current)?
    else {
        return Err("new generation could not start after completion".into());
    };
    drop(reply.send_replace(Some(state.finish(&current, Ok(snapshot())))));
    assert!(completed_with_deadline(&mut new).await?.is_ok());
    assert!(matches!(
        state.select(&current)?,
        SnapshotSelection::Cached(_)
    ));
    Ok(())
}

#[tokio::test]
async fn cancelled_joiners_do_not_release_refresh_admission_before_worker_completion() -> TestResult
{
    use super::{SnapshotSelection, SnapshotState};
    use std::sync::{Arc, atomic::AtomicUsize};
    let generation = Arc::new(AtomicUsize::new(0));
    let token = generation_token(&generation);
    let mut state = SnapshotState::default();
    let SnapshotSelection::Start { receiver, reply } = state.select(&token)? else {
        return Err("first consumer did not start refresh".into());
    };
    let SnapshotSelection::Waiting {
        receiver: joiner,
        same_generation: true,
    } = state.select(&token)?
    else {
        return Err("second consumer did not join".into());
    };
    drop(receiver);
    drop(joiner);
    assert!(state.pending.is_some());
    let SnapshotSelection::Waiting {
        receiver: mut remaining,
        same_generation: true,
    } = state.select(&token)?
    else {
        return Err("cancelled joiners released actual refresh reservation".into());
    };
    let expected = snapshot();
    drop(reply.send_replace(Some(state.finish(&token, Ok(expected.clone())))));
    let actual = completed_with_deadline(&mut remaining)
        .await?
        .map_err(io::Error::other)?;
    assert!(Arc::ptr_eq(&actual, &expected));
    assert!(state.pending.is_none());
    Ok(())
}

async fn completed_with_deadline(
    receiver: &mut super::RefreshReceiver,
) -> io::Result<super::RefreshOutcome> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        super::completed(receiver),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "shared refresh did not publish completion",
        )
    })?
}
