use std::{
    pin::Pin,
    sync::{Mutex, PoisonError},
};

use btls::{
    hpke::HpkeKey,
    ssl::{AlpnError, ExtensionType, SelectCertError, Ssl, SslEchKeys, select_next_proto},
};
use phantom_profile::browser::firefox;
use phantom_testkit::tls::{TEST_ECH_KEYS, ech_config, ech_config_list};

use super::*;
use crate::{dns::EchConfigList, tcp::AddressFamilyMemory};

const INNER: &str = "inner.phantom.test";
const PUBLIC: &str = "public.phantom.test";

#[derive(Clone, Copy)]
enum Opening {
    Ech,
    RetainingEch,
    WithoutEch,
}

#[tokio::test]
async fn ech_upgrades_authenticate_before_opening_including_retained_setups() -> TestResult<()> {
    for opening in [Opening::Ech, Opening::RetainingEch] {
        control(opening).await?;
    }
    Ok(())
}

#[tokio::test]
async fn an_upgrade_without_ech_still_offers_early_data() -> TestResult<()> {
    control(Opening::WithoutEch).await
}

async fn control(mode: Opening) -> TestResult<()> {
    let real_ech = !matches!(mode, Opening::WithoutEch);
    let identity = TestIdentity::generate_for_names(&[INNER, PUBLIC])?;
    let mut builder = identity.acceptor_builder()?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x08http/1.1", offered).ok_or(AlpnError::NOACK)
    });
    let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC);
    let configs = ech_config_list(std::slice::from_ref(&config));
    if real_ech {
        let mut keys = SslEchKeys::builder()?;
        keys.add_key(
            true,
            &config,
            HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[0].private_key)?,
        )?;
        builder.set_ech_keys(&keys.build())?;
    }
    let early_offers = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&early_offers);
    builder.set_select_certificate_callback(move |hello| {
        observed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(hello.get_extension(ExtensionType::EARLY_DATA).is_some());
        Ok::<_, SelectCertError>(())
    });
    let acceptor = builder.build();
    let connector = Http1TlsConnector::new_with_additional_roots(
        &firefox::v157_tcp_tls(),
        [identity.root_der()],
    )?
    .with_isolated_session_cache();
    let (address, listener) = loopback_listener().await?;
    let (release, released) = oneshot::channel();
    let mut peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut ssl = Ssl::new(acceptor.context())?;
        ssl.set_early_data_enabled(true);
        let mut seed = BoringStream::new(ssl, tcp)?;
        Pin::new(&mut seed).accept().await?;
        seed.write_all(b"x").await?;
        seed.flush().await?;
        let mut byte = [0; 1];
        assert_eq!(seed.read(&mut byte).await?, 0);
        let (tcp, _) = listener.accept().await?;
        released.await?;
        let mut ssl = Ssl::new(acceptor.context())?;
        ssl.set_early_data_enabled(true);
        let mut upgraded = BoringStream::new(ssl, tcp)?;
        Pin::new(&mut upgraded).accept().await?;
        let head = read_head(&mut upgraded).await?;
        assert!(head.starts_with(b"GET /socket HTTP/1.1\r\n"));
        assert_eq!(upgraded.ssl().ech_accepted(), real_ech);
        assert_eq!(upgraded.ssl().early_data_accepted(), !real_ech);
        upgraded
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        upgraded.flush().await?;
        // The request may be early data. Keep the socket until the client
        // has processed the response and closed, including its TLS Finished.
        let mut trailing = [0; 1];
        match upgraded.read(&mut trailing).await {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err("unexpected bytes after the Upgrade request".into()),
        }
        TestResult::<()>::Ok(())
    });
    let exchange = timeout(TEST_TIMEOUT, async {
        let mut seed = connector
            .tls
            .connect_with_ech(
                INNER,
                TcpStream::connect(address).await?,
                real_ech.then_some(configs.as_slice()),
            )
            .await?;
        let mut byte = [0; 1];
        seed.read_exact(&mut byte).await?;
        seed.shutdown().await?;
        drop(seed);
        let family = AddressFamilyMemory::new();
        let mut lookup = std::pin::pin!(async { real_ech.then(|| EchConfigList::new(configs)) });
        let setup = match mode {
            Opening::Ech | Opening::WithoutEch => DirectTlsSetup::Ech(lookup.as_mut()),
            Opening::RetainingEch => DirectTlsSetup::EchKeepingSlower {
                lookup: lookup.as_mut(),
                family: &family,
            },
        };
        let route = OriginRoute::Tls {
            tcp: TcpRoute::Direct(Endpoint {
                host: "127.0.0.1",
                port: address.port(),
            }),
            server_name: INNER,
            setup,
        };
        let mut opening = Box::pin(connector.open_upgrade(
            route,
            OriginForm::parse("/socket")?,
            vec![RequestHeader::new("Host", INNER)],
        ));
        let first = timeout(Duration::from_secs(1), &mut opening).await;
        if real_ech && first.is_ok() {
            return Err("real ECH upgrade returned before authenticating".into());
        }
        if !real_ech && first.is_err() {
            return Err("non-ECH upgrade waited instead of offering early data".into());
        }
        release.send(()).map_err(|_| "upgrade peer stopped")?;
        let (opening, slower) = match first {
            Ok(result) => result?,
            Err(_) => opening.await?,
        };
        if slower.is_some() {
            return Err("single-address upgrade produced a slower connection".into());
        }
        if !matches!(opening.send().await?, Http1UpgradeOutcome::Rejected(_)) {
            return Err("upgrade returned the wrong outcome".into());
        }
        Ok(())
    })
    .await;
    let result = match exchange {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    let abort_requested = result.is_err();
    if abort_requested {
        peer.abort();
    }
    let cleanup: TestResult<()> = match timeout(TEST_TIMEOUT, &mut peer).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) if abort_requested && error.is_cancelled() => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(timeout_error) => {
            peer.abort();
            match timeout(TEST_TIMEOUT, peer).await {
                Ok(Err(error)) if error.is_cancelled() => Err(timeout_error.into()),
                other => Err(format!(
                    "upgrade peer timed out: {timeout_error}; abort result: {other:?}"
                )
                .into()),
            }
        }
    };
    match (result, cleanup) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
        (Err(primary), Err(cleanup)) => {
            return Err(format!("{primary}; upgrade peer cleanup failed: {cleanup}").into());
        }
    }
    let offers = early_offers.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(*offers, [false, !real_ech]);
    Ok(())
}
