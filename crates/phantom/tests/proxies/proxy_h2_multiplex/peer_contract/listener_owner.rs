use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{net::TcpListener, time::timeout};

use super::TaskProbe;

#[derive(Clone)]
pub(super) struct ListenerWitness {
    address: SocketAddr,
    live: Arc<AtomicBool>,
}

impl ListenerWitness {
    pub(super) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(super) fn is_live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }
}

/// Observes the exact listener's destruction, independently of port reuse.
pub(crate) struct OwnedListener {
    socket: Option<TcpListener>,
    witness: ListenerWitness,
}

impl OwnedListener {
    pub(crate) fn new(socket: TcpListener, probe: Option<&TaskProbe>) -> io::Result<Self> {
        let witness = ListenerWitness {
            address: socket.local_addr()?,
            live: Arc::new(AtomicBool::new(true)),
        };
        if let Some(probe) = probe {
            probe.observe_listener(witness.clone());
        }
        Ok(Self {
            socket: Some(socket),
            witness,
        })
    }

    pub(crate) fn socket(&self) -> &TcpListener {
        match self.socket.as_ref() {
            Some(socket) => socket,
            None => panic!("owned listener is only taken during Drop"),
        }
    }
}

impl Drop for OwnedListener {
    fn drop(&mut self) {
        // Publish only after the actual listener's destructor has returned.
        drop(self.socket.take());
        self.witness.live.store(false, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn a_retained_actual_listener_keeps_its_witness_live() -> crate::support::tls::TestResult<()>
{
    let probe = TaskProbe::default();
    let socket = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = socket.local_addr()?;
    let listener = OwnedListener::new(socket, Some(&probe))?;
    let client = timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(address),
    )
    .await??;
    let (accepted, _) = timeout(Duration::from_secs(5), listener.socket().accept()).await??;
    assert_eq!(probe.live_listeners(), [address]);
    drop(listener);
    // Accepted and external client sockets outlive the exact listener.
    assert!(probe.live_listeners().is_empty());
    drop(accepted);
    drop(client);
    Ok(())
}

#[tokio::test]
async fn releasing_one_listener_preserves_the_other_listener_witness()
-> crate::support::tls::TestResult<()> {
    let probe = TaskProbe::default();
    let first_socket = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let first_address = first_socket.local_addr()?;
    let first = OwnedListener::new(first_socket, Some(&probe))?;
    let second_socket = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let second_address = second_socket.local_addr()?;
    let second = OwnedListener::new(second_socket, Some(&probe))?;
    assert_ne!(first_address, second_address);
    assert_eq!(probe.live_listeners(), [first_address, second_address]);
    drop(first);
    assert_eq!(probe.live_listeners(), [second_address]);
    drop(second);
    assert!(probe.live_listeners().is_empty());
    Ok(())
}
