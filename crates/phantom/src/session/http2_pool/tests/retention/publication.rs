use std::{
    future::Future as _,
    sync::{Mutex, PoisonError, Weak},
    task::{Context, Poll, Wake, Waker},
};

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Published {
    slots: usize,
    spares: usize,
    connecting: bool,
}

struct PublicationWake {
    entry: Weak<PoolEntry>,
    observed: Mutex<Option<Published>>,
}

impl Wake for PublicationWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(entry) = self.entry.upgrade() {
            let state = entry.lock();
            *self.observed.lock().unwrap_or_else(PoisonError::into_inner) = Some(Published {
                slots: state.slots.len(),
                spares: state.spares.len(),
                connecting: state.connecting,
            });
        }
    }
}

#[tokio::test]
async fn setup_waiters_see_the_registered_backup_when_the_winner_is_published() -> TestResult {
    for maximum in [1, 2] {
        tokio::time::timeout(Duration::from_secs(2), async {
            let one = NonZeroUsize::MIN;
            let bound = NonZeroUsize::new(maximum).ok_or("zero connection limit")?;
            let pool = Http2Pool::new(one, one, one).with_max_connections(bound);
            let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
            let mode = super::super::super::Http2ConnectionMode::TlsOrigin;
            let entry = pool
                .entry(PoolKey::new(&endpoint, &Route::Direct, mode))
                .await;
            let (winner, _winner_peer) = connection().await?;
            let (backup, _backup_peer) = connection().await?;
            let (release, released) = oneshot::channel();
            let slower = SlowerConnection::new(connected_progress(), async move {
                let _ = released.await;
                Some(backup)
            });
            let wake = Arc::new(PublicationWake {
                entry: Arc::downgrade(&entry),
                observed: Mutex::new(None),
            });
            let waker = Waker::from(Arc::clone(&wake));
            let mut notified = std::pin::pin!(entry.setup_done.notified());
            notified.as_mut().enable();
            assert!(matches!(
                notified.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Pending
            ));
            let lease = reserve(&entry).finish(winner, Some(slower));
            assert_eq!(
                *wake.observed.lock().unwrap_or_else(PoisonError::into_inner),
                Some(Published {
                    slots: 1,
                    spares: 1,
                    connecting: false
                }),
                "notification exposed winner publication without its backup"
            );
            if maximum == 1 {
                entry.invalidate(&lease.token).await;
            } else {
                assert_eq!(entry.lock().choose(), super::super::super::Choice::Open);
            }
            let connector = phantom_net::http2::Http2TlsConnector::new(
                &phantom_profile::browser::firefox::v157_tcp_tls(),
                &phantom_profile::browser::firefox::v157_http2(),
            )?;
            {
                let mut competing = std::pin::pin!(entry.acquire(
                    &connector,
                    None,
                    &endpoint,
                    &Route::Direct,
                    mode,
                ));
                assert!(poll_once(competing.as_mut()).is_none());
                let state = entry.lock();
                assert!(!state.connecting, "waiter reserved a duplicate setup");
                assert_eq!(state.spares.len(), 1);
            }
            let mut completed = std::pin::pin!(entry.setup_done.notified());
            completed.as_mut().enable();
            release.send(()).map_err(|_| "backup task disappeared")?;
            completed.await;
            let state = entry.lock();
            assert!(!state.connecting);
            assert!(state.spares.is_empty());
            assert_eq!(state.slots.len(), maximum);
            drop(state);
            drop(lease);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn a_stale_backup_cannot_install_while_another_setup_is_reserved() -> TestResult {
    let entry = cold_entry().await?;
    let (backup, mut backup_peer) = connection().await?;
    let (release, released) = oneshot::channel();
    adopt(
        &entry,
        SlowerConnection::new(connected_progress(), async move {
            let _ = released.await;
            Some(backup)
        }),
    );
    // Force the old interleaving: a replacement already owns setup when an
    // older registered backup reports completion.
    let reservation = reserve(&entry);
    let mut completed = std::pin::pin!(entry.setup_done.notified());
    completed.as_mut().enable();
    release.send(()).map_err(|_| "backup task disappeared")?;
    tokio::time::timeout(Duration::from_secs(1), completed).await?;
    {
        let state = entry.lock();
        assert!(state.connecting);
        assert!(state.spares.is_empty());
        assert!(
            state.slots.is_empty(),
            "late backup installed beside a reservation"
        );
    }
    use tokio::io::AsyncReadExt as _;
    let mut frames = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), backup_peer.read_to_end(&mut frames)).await??;
    assert!(frames.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    let (replacement, _replacement_peer) = connection().await?;
    drop(reservation.finish(replacement, None));
    assert_eq!(entry.lock().slots.len(), 1);
    assert!(!entry.lock().connecting);
    Ok(())
}
