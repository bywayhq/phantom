use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    sync::{OnceLock, Weak, atomic::AtomicU8, mpsc},
    thread,
};

use super::*;
use crate::operations::tests::test_global;

struct DropProbe {
    owner: Arc<OnceLock<Weak<Owner>>>,
    observed: Arc<AtomicU8>,
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        let Some(owner) = self.owner.get().and_then(Weak::upgrade) else {
            self.observed.store(4, Ordering::SeqCst);
            return;
        };
        let result = if !owner.busy.load(Ordering::SeqCst) {
            2
        } else if owner.source.try_lock().is_err() {
            3
        } else {
            1
        };
        self.observed.store(result, Ordering::SeqCst);
    }
}

fn peer() -> Result<(SocketAddr, thread::JoinHandle<std::io::Result<()>>), Failure> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| Failure::new("test_bind"))?;
    let address = listener
        .local_addr()
        .map_err(|_| Failure::new("test_address"))?;
    let task = thread::spawn(move || {
        let (mut connection, _) = listener.accept()?;
        connection.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut head = Vec::new();
        let mut byte = [0];
        while head.len() < 16 * 1024 && !head.ends_with(b"\r\n\r\n") {
            connection.read_exact(&mut byte)?;
            head.push(byte[0]);
        }
        connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    });
    Ok((address, task))
}

fn client() -> Result<phantom::Client, Failure> {
    let config = serde_json::from_value(serde_json::json!({
        "profile":"chrome-154-windows", "protocol":"h1", "cookies":false
    }))
    .map_err(|_| Failure::new("test_config"))?;
    Ok(crate::client::NativeClient::new(config)?.client)
}

fn owner(source: SseEventSource) -> Arc<Owner> {
    Arc::new(Owner {
        client: 1,
        source: Mutex::new(Some(Box::new(source))),
        closed: AtomicBool::new(false),
        busy: AtomicBool::new(false),
        changed: Notify::new(),
        hooks: None,
    })
}

#[test]
fn closed_read_drops_source_before_publishing_idle() -> Result<(), Failure> {
    let global = test_global()?;
    let (address, peer) = peer()?;
    let owner_slot = Arc::new(OnceLock::new());
    let observed = Arc::new(AtomicU8::new(0));
    let probe = DropProbe {
        owner: Arc::clone(&owner_slot),
        observed: Arc::clone(&observed),
    };
    let client = client()?;
    let response = global.runtime.block_on(async {
        client
            .event_source(HttpProtocol::Http1, &format!("http://{address}/"))
            .map_err(Failure::from)?
            .header_hook(move |_| {
                let _keep_alive = &probe;
                Ok(())
            })
            .connect()
            .await
            .map_err(|_| Failure::new("test_connect"))
    })?;
    peer.join()
        .map_err(|_| Failure::new("test_peer_panicked"))?
        .map_err(|_| Failure::new("test_peer"))?;
    let owner = owner(response.into_body());
    owner_slot
        .set(Arc::downgrade(&owner))
        .map_err(|_| Failure::new("test_owner"))?;
    assert_eq!(observed.load(Ordering::SeqCst), 0);
    let lease = owner.take()?;
    assert!(owner.close().is_none());
    drop(lease);

    assert_eq!(
        observed.load(Ordering::SeqCst),
        1,
        "source must drop while busy, outside its mutex"
    );
    assert!(!owner.busy.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn closing_retained_callback_drops_it_outside_registry_before_idle() -> Result<(), Failure> {
    let global = test_global()?;
    let (address, peer) = peer()?;
    let client = client()?;
    let (operation, _cancel) = global.lock().reserve(Target::Request(1))?;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let owner_slot = Arc::new(OnceLock::new());
    let observed = Arc::new(AtomicU8::new(0));
    let probe = DropProbe {
        owner: Arc::clone(&owner_slot),
        observed: Arc::clone(&observed),
    };
    let response = global.runtime.block_on(async {
        client
            .event_source(HttpProtocol::Http1, &format!("http://{address}/"))
            .map_err(Failure::from)?
            .initial_retry(Duration::ZERO)
            .async_header_hook(move |context| {
                let _keep_alive = &probe;
                let calls = Arc::clone(&calls);
                Box::pin(async move {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        return Ok(());
                    }
                    global.header_hook(operation, 0, context).await
                })
            })
            .connect()
            .await
            .map_err(|_| Failure::new("test_connect"))
    })?;
    peer.join()
        .map_err(|_| Failure::new("test_peer_panicked"))?
        .map_err(|_| Failure::new("test_peer"))?;
    let owner = owner(response.into_body());
    owner_slot
        .set(Arc::downgrade(&owner))
        .map_err(|_| Failure::new("test_owner"))?;
    global.runtime.block_on(async {
        let mut read = Box::pin(owner.take()?.read());
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let polled = std::future::poll_fn(|context| {
                    std::task::Poll::Ready(std::future::Future::poll(read.as_mut(), context))
                })
                .await;
                assert!(polled.is_pending());
                if global.lock().operations[&operation].callback_call.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| Failure::new("test_callback_not_pending"))?;
        // Cancellation restores the core source, including its pending GET.
        drop(read);
        Ok::<(), Failure>(())
    })?;
    assert!(!owner.busy.load(Ordering::SeqCst));
    assert!(
        global.lock().operations[&operation]
            .callback_call
            .as_ref()
            .is_some_and(|call| call.reply.is_some())
    );
    let (completed, received) = mpsc::channel();
    let closed = Arc::clone(&owner);
    let close_task = thread::spawn(move || {
        let mut closed_sources = Vec::new();
        {
            let mut state = global.lock();
            state.sources.insert(2, closed);
            state.close_source(2, &mut closed_sources);
        }
        drop(closed_sources);
        let cleared = global.lock().operations[&operation]
            .callback_call
            .as_ref()
            .is_some_and(|call| call.reply.is_none());
        let _ = completed.send(cleared);
    });
    // This is a bound on a missing handback, not a timing-based ordering check.
    assert!(
        received
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| Failure::new("test_close_deadlocked"))?
    );
    close_task
        .join()
        .map_err(|_| Failure::new("test_close_panicked"))?;
    assert_eq!(
        observed.load(Ordering::SeqCst),
        1,
        "retired source must drop while busy, outside its mutex"
    );
    assert!(!owner.busy.load(Ordering::SeqCst));
    Ok(())
}
