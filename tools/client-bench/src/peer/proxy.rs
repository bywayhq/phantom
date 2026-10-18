use super::{Result, Stats, delay, read_head};
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};

fn connect_target(head: &str, authenticated: bool) -> Result<Option<SocketAddr>> {
    let mut fields = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut fields);
    if !request.parse(head.as_bytes())?.is_complete() || request.method != Some("CONNECT") {
        return Err("expected a complete CONNECT head".into());
    }
    let target = request.path.ok_or("missing CONNECT target")?.parse()?;
    let mut credentials = request
        .headers
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case("proxy-authorization"));
    let credential = credentials.next();
    if credentials.next().is_some() {
        return Err("duplicate proxy credentials".into());
    }
    if authenticated {
        let valid = credential
            .and_then(|field| std::str::from_utf8(field.value).ok())
            .and_then(|value| value.split_once(' '))
            .is_some_and(|(scheme, value)| {
                scheme.eq_ignore_ascii_case("basic") && value == "YmVuY2g6YmVuY2g="
            });
        if !valid {
            return Ok(None);
        }
    } else if credential.is_some() {
        return Err("unexpected proxy credentials".into());
    }
    Ok(Some(target))
}

pub(super) async fn serve(
    socket: TcpStream,
    targets: Arc<Vec<SocketAddr>>,
    socks: bool,
    delay_ms: u64,
    authenticated: bool,
    stats: &Stats,
) -> Result<()> {
    if delay_ms == 0 {
        return proxy_stream(socket, targets, socks, authenticated, stats).await;
    }
    let (stream, relay) = tokio::io::duplex(64 * 1024);
    tokio::try_join!(
        proxy_stream(stream, targets, socks, authenticated, stats),
        async {
            delay::relay(socket, relay, Duration::from_millis(delay_ms)).await?;
            Result::Ok(())
        },
    )?;
    Ok(())
}

async fn proxy_stream<S: AsyncRead + AsyncWrite + Unpin>(
    socket: S,
    targets: Arc<Vec<SocketAddr>>,
    socks: bool,
    authenticated: bool,
    stats: &Stats,
) -> Result<()> {
    let mut stream = BufReader::new(socket);
    let target: SocketAddr = if socks {
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting != [5, 1] || stream.read_u8().await? != 0 {
            return Err("expected unauthenticated SOCKS5".into());
        }
        stream.get_mut().write_all(&[5, 0]).await?;
        let mut request = [0; 4];
        stream.read_exact(&mut request).await?;
        if request != [5, 1, 0, 1] {
            return Err("expected IPv4 SOCKS5 CONNECT".into());
        }
        let mut ip = [0; 4];
        stream.read_exact(&mut ip).await?;
        SocketAddr::from((ip, stream.read_u16().await?))
    } else {
        let head = read_head(&mut stream).await?.ok_or("missing CONNECT")?;
        let Some(target) = connect_target(&head, authenticated)? else {
            stats.proxy_auth_challenges.fetch_add(1, Ordering::Relaxed);
            stream.get_mut().write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"benchmark\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            stream.get_mut().flush().await?;
            return Ok(());
        };
        target
    };
    if !targets.contains(&target) {
        return Err("proxy target is not a benchmark origin".into());
    }
    let mut origin = TcpStream::connect(target).await?;
    stats.proxy_tunnels.fetch_add(1, Ordering::Relaxed);
    if authenticated {
        stats
            .proxy_authenticated_connections
            .fetch_add(1, Ordering::Relaxed);
    }
    origin.set_nodelay(true)?;
    if socks {
        stream
            .get_mut()
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await?;
    } else {
        stream
            .get_mut()
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }
    tokio::io::copy_bidirectional(&mut stream, &mut origin).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_authentication_distinguishes_challenges_from_malformed_requests() -> Result<()> {
        let target = "127.0.0.1:1234".parse()?;
        for credentials in ["", "Proxy-Authorization: Basic wrong\r\n"] {
            assert!(
                connect_target(
                    &format!("CONNECT {target} HTTP/1.1\r\n{credentials}\r\n"),
                    true
                )?
                .is_none()
            );
        }
        let valid = format!(
            "CONNECT {target} HTTP/1.1\r\nProxy-Authorization: Basic YmVuY2g6YmVuY2g=\r\n\r\n"
        );
        assert_eq!(connect_target(&valid, true)?, Some(target));
        assert!(connect_target(&valid, false).is_err());
        assert!(connect_target("GET / HTTP/1.1\r\n\r\n", true).is_err());
        assert!(
            connect_target(
                &valid.replace("\r\n\r\n", "\r\nProxy-Authorization: Basic other\r\n\r\n"),
                true
            )
            .is_err()
        );
        Ok(())
    }
    #[tokio::test]
    async fn rejected_credentials_return_a_challenge_without_contacting_the_origin() -> Result<()> {
        use tokio::{io::AsyncReadExt, net::TcpListener};
        let origin = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let target = origin.local_addr()?;
        for credentials in ["", "Proxy-Authorization: Basic wrong\r\n"] {
            let (mut caller, peer) = tokio::io::duplex(4096);
            let stats = Stats::default();
            let targets = Arc::new(vec![target]);
            let (caller_result, result) = tokio::join!(
                async {
                    caller
                        .write_all(
                            format!("CONNECT {target} HTTP/1.1\r\n{credentials}\r\n").as_bytes(),
                        )
                        .await?;
                    let mut response = String::new();
                    caller.read_to_string(&mut response).await?;
                    assert!(response.starts_with("HTTP/1.1 407 "));
                    assert!(response.contains("Proxy-Authenticate: Basic"));
                    Result::Ok(())
                },
                proxy_stream(peer, targets, false, true, &stats)
            );
            caller_result?;
            result?;
            assert_eq!(stats.proxy_auth_challenges.load(Ordering::Relaxed), 1);
            assert_eq!(
                stats
                    .proxy_authenticated_connections
                    .load(Ordering::Relaxed),
                0
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(50), origin.accept())
                    .await
                    .is_err()
            );
        }
        Ok(())
    }
}
