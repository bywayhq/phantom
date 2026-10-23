use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Peers {
    None,
    Silent,
    SilentAndIdle,
}

impl Peers {
    pub(super) const fn count(self) -> usize {
        match self {
            Self::None => 0,
            Self::Silent => 1,
            Self::SilentAndIdle => 2,
        }
    }
}

pub(super) struct Spares {
    silent: Option<TcpStream>,
    idle: Option<SslStream<TcpStream>>,
}

pub(super) async fn connect(
    peers: Peers,
    connector: &SslConnector,
    scope: &SslSessionScope,
    list: &[u8],
    address: SocketAddr,
    accepted: oneshot::Receiver<()>,
) -> CaptureResult<Spares> {
    let silent = if peers == Peers::None {
        None
    } else {
        let tcp = TcpStream::connect(address).await?;
        // The origin task must own this socket before the actual seed starts.
        accepted.await?;
        Some(tcp)
    };
    let idle = if peers == Peers::SilentAndIdle {
        let ssl = fresh_ssl(connector, scope, list)?;
        let mut tls = SslStream::new(ssl, TcpStream::connect(address).await?)?;
        Pin::new(&mut tls).connect().await?;
        if !tls.ssl().is_init_finished() || !tls.ssl().ech_accepted() {
            return Err("idle TLS spare did not finish authenticated ECH".into());
        }
        Some(tls)
    } else {
        None
    };
    Ok(Spares { silent, idle })
}

impl Spares {
    pub(super) async fn retired(
        mut self,
        connector: &SslConnector,
        scope: &SslSessionScope,
        list: &[u8],
    ) -> CaptureResult<()> {
        if let Some(mut tls) = self.idle.take() {
            let request = format!("GET {RESUME} HTTP/1.1\r\nhost: {HOSTNAME}\r\n\r\n");
            let result = async {
                tls.write_all(request.as_bytes()).await?;
                tls.flush().await?;
                tls.read(&mut [0_u8; 1]).await
            }
            .await;
            disconnected(result, "pre-seed TLS spare served the probe")?;
        }
        if let Some(tcp) = self.silent.take() {
            let ssl = fresh_ssl(connector, scope, list)?;
            let mut tls = SslStream::new(ssl, tcp)?;
            match Pin::new(&mut tls).connect().await {
                Ok(()) => return Err("pre-ClientHello TCP spare survived probe release".into()),
                Err(error) if error.code() == ErrorCode::SYSCALL && error.io_error().is_none() => {}
                Err(error) => match error.into_io_error() {
                    Ok(error) => disconnected(Err(error), "pre-ClientHello spare remained open")?,
                    Err(error) => return Err(error.into()),
                },
            }
        }
        Ok(())
    }
}

fn fresh_ssl(connector: &SslConnector, scope: &SslSessionScope, list: &[u8]) -> CaptureResult<Ssl> {
    let mut ssl = connector
        .configure()?
        .into_ssl_with_scoped_session(HOSTNAME, scope, None, |_| {})?
        .ok_or("spare scoped session rejected")?;
    ssl.set_ech_config_list(list)?;
    ssl.set_early_data_enabled(true);
    Ok(ssl)
}

fn disconnected(result: io::Result<usize>, alive: &'static str) -> CaptureResult<()> {
    match result {
        Ok(0) => Ok(()),
        Ok(_) => Err(alive.into()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[tokio::test]
async fn seed_retires_pre_clienthello_tcp_before_releasing_the_probe() -> CaptureResult<()> {
    sequence(Mode::EarlyAccept, Peers::Silent).await
}

#[tokio::test]
async fn seed_retires_idle_tls_and_pre_clienthello_spares_before_the_probe() -> CaptureResult<()> {
    sequence(Mode::EarlyAccept, Peers::SilentAndIdle).await
}
