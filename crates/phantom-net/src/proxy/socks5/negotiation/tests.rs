use std::{
    error::Error as _,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    time::timeout,
};

use super::{Command, Error, Socks5Auth, Socks5ErrorKind, authenticate};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const DEADLINE: Duration = Duration::from_secs(5);

mod connect;

#[tokio::test]
async fn both_commands_exchange_exact_auth_bytes_under_backpressure() -> TestResult {
    for command in [Command::Connect, Command::Associate] {
        for method in [0, 2] {
            let (stream, mut proxy) = duplex(1);
            let flushes = Arc::new(AtomicUsize::new(0));
            let mut stream = Fragmented {
                inner: stream,
                flushes: flushes.clone(),
            };
            let client = authenticate(
                &mut stream,
                Socks5Auth::UsernamePassword {
                    username: "user",
                    password: "secret",
                },
                command,
            );
            let peer = async {
                let mut greeting = [0; 4];
                proxy.read_exact(&mut greeting).await?;
                assert_eq!(greeting, [5, 2, 0, 2]);
                proxy.write_all(&[5, method]).await?;
                if method == 2 {
                    let mut credentials = [0; 13];
                    proxy.read_exact(&mut credentials).await?;
                    assert_eq!(&credentials, b"\x01\x04user\x06secret");
                    proxy.write_all(&[1, 0]).await?;
                }
                Ok::<_, io::Error>(())
            };
            let (result, observed) =
                timeout(DEADLINE, async { tokio::join!(client, peer) }).await?;
            result?;
            observed?;
            let expected = if matches!(command, Command::Associate) {
                if method == 2 { 2 } else { 1 }
            } else {
                0
            };
            assert_eq!(flushes.load(Ordering::Relaxed), expected);
        }
    }
    Ok(())
}

#[tokio::test]
async fn failed_method_selection_sends_no_credentials_or_command() -> TestResult {
    for command in [Command::Connect, Command::Associate] {
        for (reply, expected) in [
            ([4, 0], Socks5ErrorKind::Negotiation),
            ([5, 3], Socks5ErrorKind::Negotiation),
            ([5, 0xff], Socks5ErrorKind::Authentication),
            ([5, 2], Socks5ErrorKind::Authentication),
        ] {
            let (mut client, mut proxy) = duplex(64);
            let peer = tokio::spawn(async move {
                let mut greeting = [0; 3];
                proxy.read_exact(&mut greeting).await?;
                assert_eq!(greeting, [5, 1, 0]);
                proxy.write_all(&reply).await?;
                let mut remaining = Vec::new();
                proxy.read_to_end(&mut remaining).await?;
                Ok::<_, io::Error>(remaining)
            });
            let result = timeout(
                DEADLINE,
                authenticate(&mut client, Socks5Auth::None, command),
            )
            .await?;
            let error = result.err().ok_or("invalid method selection succeeded")?;
            assert_eq!(error.kind(), expected);
            if matches!(command, Command::Connect) {
                assert!(
                    error
                        .source()
                        .and_then(|source| source.downcast_ref::<Error>())
                        .is_some()
                );
            }
            drop(client);
            assert!(timeout(DEADLINE, peer).await???.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn password_failure_preserves_categories_and_redacts_credentials() -> TestResult {
    for command in [Command::Connect, Command::Associate] {
        for (reply, expected) in [
            ([5, 0], Socks5ErrorKind::Negotiation),
            ([1, 7], Socks5ErrorKind::Authentication),
        ] {
            let (mut client, mut proxy) = duplex(64);
            let peer = tokio::spawn(async move {
                let mut greeting = [0; 4];
                proxy.read_exact(&mut greeting).await?;
                assert_eq!(greeting, [5, 2, 0, 2]);
                proxy.write_all(&[5, 2]).await?;
                let mut credentials = [0; 13];
                proxy.read_exact(&mut credentials).await?;
                assert_eq!(&credentials, b"\x01\x04user\x06secret");
                proxy.write_all(&reply).await?;
                let mut remaining = Vec::new();
                proxy.read_to_end(&mut remaining).await?;
                Ok::<_, io::Error>(remaining)
            });
            let result = timeout(
                DEADLINE,
                authenticate(
                    &mut client,
                    Socks5Auth::UsernamePassword {
                        username: "user",
                        password: "secret",
                    },
                    command,
                ),
            )
            .await?;
            let error = result.err().ok_or("invalid password response succeeded")?;
            assert_eq!(error.kind(), expected);
            let diagnostic = format!("{error:?} {error}");
            assert!(!diagnostic.contains("user"));
            assert!(!diagnostic.contains("secret"));
            if matches!(command, Command::Connect) {
                let source = error
                    .source()
                    .and_then(|source| source.downcast_ref::<Error>());
                assert!(matches!(
                    (reply[0], source),
                    (5, Some(Error::InvalidResponseVersion))
                        | (1, Some(Error::PasswordAuthFailure(7)))
                ));
            }
            drop(client);
            assert!(timeout(DEADLINE, peer).await???.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_authentication_closes_the_owned_stream_without_more_bytes() -> TestResult {
    for command in [Command::Connect, Command::Associate] {
        for method in [0, 2] {
            let (mut client, mut proxy) = duplex(64);
            let task = tokio::spawn(async move {
                let auth = if method == 0 {
                    Socks5Auth::None
                } else {
                    Socks5Auth::UsernamePassword {
                        username: "user",
                        password: "secret",
                    }
                };
                authenticate(&mut client, auth, command).await
            });
            let mut greeting = vec![0; if method == 0 { 3 } else { 4 }];
            timeout(DEADLINE, proxy.read_exact(&mut greeting)).await??;
            if method == 0 {
                assert_eq!(greeting, [5, 1, 0]);
            } else {
                assert_eq!(greeting, [5, 2, 0, 2]);
                proxy.write_all(&[5, 2]).await?;
                let mut credentials = [0; 13];
                timeout(DEADLINE, proxy.read_exact(&mut credentials)).await??;
                assert_eq!(&credentials, b"\x01\x04user\x06secret");
            }

            task.abort();
            assert!(task.await.is_err_and(|error| error.is_cancelled()));
            let mut remaining = Vec::new();
            timeout(DEADLINE, proxy.read_to_end(&mut remaining)).await??;
            assert!(remaining.is_empty());
        }
    }
    Ok(())
}

struct Fragmented {
    inner: DuplexStream,
    flushes: Arc<AtomicUsize>,
}

impl AsyncRead for Fragmented {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut byte = [0];
        let mut read = ReadBuf::new(&mut byte);
        match Pin::new(&mut self.inner).poll_read(context, &mut read) {
            Poll::Ready(Ok(())) => {
                buffer.put_slice(read.filled());
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl AsyncWrite for Fragmented {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, &buffer[..buffer.len().min(1)])
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
