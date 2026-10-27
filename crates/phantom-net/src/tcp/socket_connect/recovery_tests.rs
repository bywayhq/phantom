use std::{
    cell::Cell, error::Error, future::Future, net::Ipv4Addr, num::NonZeroU32, rc::Rc, task::Poll,
    time::Duration,
};

use phantom_profile::TcpPortRandomization;
use tokio::{net::TcpListener, time::timeout};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

fn settings() -> TcpSettings {
    TcpSettings {
        nodelay: true,
        send_buffer_size: NonZeroU32::new(32_768),
        port_randomization: Some(TcpPortRandomization {
            // Exercise recovery independently of browser profile build requirements.
            minimum_windows_build: 0,
        }),
        ..TcpSettings::default()
    }
}

#[tokio::test]
async fn an_unallocated_randomized_socket_gets_one_fresh_attempt() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let settings = settings();
    let socket = prepare(address, Some(settings), None)?;
    let expected_buffer = socket.send_buffer_size()?;
    let mut calls = 0;

    let stream = timeout(
        Duration::from_secs(8),
        connect_with(
            socket,
            address,
            Some(settings),
            None,
            |socket, address| {
                calls += 1;
                assert!(socket.tcp_nodelay()?);
                assert_eq!(socket.send_buffer_size()?, expected_buffer);
                assert!(crate::socket_ffi::port_randomization::is_enabled(
                    std::os::windows::io::AsSocket::as_socket(socket)
                )?);
                if calls == 1 {
                    return Err(io::Error::from_raw_os_error(10055));
                }
                socket.connect(&address.into())
            },
            complete,
        ),
    )
    .await?
    .map_err(Failure::into_error)?;

    assert_eq!(calls, 2);
    assert_eq!(stream.peer_addr()?, address);
    let (mut peer, _) = listener.accept().await?;
    drop(stream);
    let mut byte = [0];
    assert_eq!(
        tokio::io::AsyncReadExt::read(&mut peer, &mut byte).await?,
        0
    );
    Ok(())
}

#[tokio::test]
async fn a_second_failure_keeps_both_errors_and_does_not_try_again() -> TestResult {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let settings = settings();
    let socket = prepare(address, Some(settings), None)?;
    let mut calls = 0;

    let result = connect_with(
        socket,
        address,
        Some(settings),
        None,
        |_, _| {
            calls += 1;
            Err(io::Error::from_raw_os_error(if calls == 1 {
                10055
            } else {
                10061
            }))
        },
        complete,
    )
    .await;

    let Err(Failure::Initial(error)) = result else {
        return Err(format!("expected an initial failure, got {result:?}").into());
    };
    assert_eq!(calls, 2);
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    let context = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RetryError>())
        .ok_or("missing retry context")?;
    assert_eq!(context.first.raw_os_error(), Some(10055));
    assert_eq!(context.retry.raw_os_error(), Some(10061));
    assert!(context.source().is_some());
    Ok(())
}

#[tokio::test]
async fn a_refused_fresh_connection_keeps_its_completion_stage() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    drop(listener);
    let settings = settings();
    let socket = prepare(address, Some(settings), None)?;
    let mut calls = 0;

    let result = timeout(
        Duration::from_secs(8),
        connect_with(
            socket,
            address,
            Some(settings),
            None,
            |socket, address| {
                calls += 1;
                if calls == 1 {
                    return Err(io::Error::from_raw_os_error(10055));
                }
                socket.connect(&address.into())
            },
            complete,
        ),
    )
    .await?;

    assert_eq!(calls, 2);
    let Err(Failure::Continuation(error)) = result else {
        return Err(format!("expected an asynchronous refusal, got {result:?}").into());
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert!(error.to_string().contains("10055"));
    Ok(())
}

#[tokio::test]
async fn another_error_or_disabled_randomization_never_replaces_the_socket() -> TestResult {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    for (settings, code) in [
        (Some(settings()), 10061),
        (Some(TcpSettings::default()), 10055),
        (
            Some(TcpSettings {
                port_randomization: Some(TcpPortRandomization {
                    minimum_windows_build: u32::MAX,
                }),
                ..TcpSettings::default()
            }),
            10055,
        ),
        (None, 10055),
    ] {
        let socket = prepare(address, settings, None)?;
        let mut calls = 0;
        let result = connect_with(
            socket,
            address,
            settings,
            None,
            |_, _| {
                calls += 1;
                Err(io::Error::from_raw_os_error(code))
            },
            complete,
        )
        .await;

        assert_eq!(calls, 1);
        let Err(Failure::Initial(error)) = result else {
            return Err(format!("expected an initial failure, got {result:?}").into());
        };
        assert_eq!(error.raw_os_error(), Some(code));
    }
    Ok(())
}

#[tokio::test]
async fn an_assigned_source_port_never_gets_a_replacement() -> TestResult {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let settings = settings();
    let source = SourceBinding::new().with_address(Ipv4Addr::LOCALHOST.into());
    let socket = prepare(address, Some(settings), Some(&source))?;
    assert_ne!(socket.local_addr()?.as_socket().map(|s| s.port()), Some(0));
    let mut calls = 0;

    let result = connect_with(
        socket,
        address,
        Some(settings),
        Some(&source),
        |_, _| {
            calls += 1;
            Err(io::Error::from_raw_os_error(10055))
        },
        complete,
    )
    .await;

    assert_eq!(calls, 1);
    assert!(matches!(result, Err(Failure::Initial(_))));
    Ok(())
}

#[tokio::test]
async fn asynchronous_10055_never_starts_another_socket() -> TestResult {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let socket = prepare(address, Some(settings()), None)?;
    let mut calls = 0;
    let result = connect_with(
        socket,
        address,
        Some(settings()),
        None,
        |_, _| {
            calls += 1;
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        },
        |socket| async move {
            drop(socket);
            Err(Failure::Continuation(io::Error::from_raw_os_error(10055)))
        },
    )
    .await;

    assert_eq!(calls, 1);
    let Err(Failure::Continuation(error)) = result else {
        return Err(format!("expected a completion failure, got {result:?}").into());
    };
    assert_eq!(error.raw_os_error(), Some(10055));
    Ok(())
}

struct PendingSocket {
    _socket: Socket,
    drops: Rc<Cell<usize>>,
}

impl Drop for PendingSocket {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

async fn pending(socket: Socket, drops: Rc<Cell<usize>>) -> Result<TcpStream, Failure> {
    let _owner = PendingSocket {
        _socket: socket,
        drops,
    };
    std::future::pending().await
}

#[tokio::test]
async fn cancelling_a_pending_replacement_drops_its_socket() -> TestResult {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let socket = prepare(address, Some(settings()), None)?;
    let drops = Rc::new(Cell::new(0));
    let observed_drops = Rc::clone(&drops);
    let calls = Cell::new(0);
    let mut connect = Box::pin(connect_with(
        socket,
        address,
        Some(settings()),
        None,
        |_, _| {
            calls.set(calls.get() + 1);
            Err(io::Error::from_raw_os_error(if calls.get() == 1 {
                10055
            } else {
                10035
            }))
        },
        |socket| pending(socket, drops),
    ));
    std::future::poll_fn(|context| match connect.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(result) => panic!("expected a pending replacement, got {result:?}"),
    })
    .await;

    assert_eq!(calls.get(), 2);
    assert_eq!(observed_drops.get(), 0);
    drop(connect);
    assert_eq!(observed_drops.get(), 1);
    Ok(())
}

#[tokio::test]
async fn the_original_deadline_cancels_a_pending_replacement() -> TestResult {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let socket = prepare(address, Some(settings()), None)?;
    let drops = Rc::new(Cell::new(0));
    let observed_drops = Rc::clone(&drops);
    let calls = Cell::new(0);
    let deadline = tokio::time::Instant::now();
    let connect = connect_with(
        socket,
        address,
        Some(settings()),
        None,
        |_, _| {
            calls.set(calls.get() + 1);
            Err(io::Error::from_raw_os_error(if calls.get() == 1 {
                10055
            } else {
                10035
            }))
        },
        |socket| pending(socket, drops),
    );

    let result = tokio::time::timeout_at(deadline, connect).await;

    assert!(result.is_err());
    assert_eq!(calls.get(), 2);
    assert_eq!(observed_drops.get(), 1);
    Ok(())
}
