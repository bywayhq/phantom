//! `SO_RANDOMIZE_PORT` follows the profile from its minimum Windows build.

use crate::tcp::reaches_build;

#[test]
fn port_randomization_starts_at_the_minimum_build() {
    // Windows 10 22H2, Server 2022, and Windows 11 21H2 come before 22621.
    assert!(!reaches_build(10, 19_045, 22_621));
    assert!(!reaches_build(10, 20_348, 22_621));
    assert!(!reaches_build(10, 22_000, 22_621));
    assert!(reaches_build(10, 22_621, 22_621));
    assert!(reaches_build(10, 26_200, 22_621));
    // Windows 8.1 is version 6.3; a later major version is past every build.
    assert!(!reaches_build(6, 9_600, 0));
    assert!(reaches_build(11, 0, 22_621));
}

#[cfg(windows)]
mod on_windows {
    use std::{net::Ipv4Addr, os::windows::io::AsSocket};

    use phantom_profile::{TcpPortRandomization, TcpSettings, chromium, firefox};
    use tokio::net::TcpListener;

    use super::super::{TestResult, sets_random_port};
    use crate::{
        SourceBinding,
        tcp::{ProfileTcpStream, connect},
        windows_port_randomization,
    };

    /// Opens `count` connections to a loopback listener one after another and
    /// keeps them all open.
    async fn connections(
        settings: TcpSettings,
        source: Option<&SourceBinding>,
        count: usize,
    ) -> TestResult<Vec<ProfileTcpStream>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let mut streams = Vec::new();
        for _ in 0..count {
            streams.push(connect("127.0.0.1", port, Some(settings), source, None).await?);
        }
        Ok(streams)
    }

    fn random_port(stream: &ProfileTcpStream) -> TestResult<bool> {
        Ok(windows_port_randomization::is_enabled(stream.as_socket())?)
    }

    /// Whether some pair of successive local ports lies far apart. Windows
    /// hands out sequential ports one apart when nothing else takes one in
    /// between; random ones from the dynamic range almost never stay within
    /// 64 of each other seven times running.
    fn scattered(streams: &[ProfileTcpStream]) -> TestResult<bool> {
        let ports = streams
            .iter()
            .map(|stream| Ok(stream.local_addr()?.port()))
            .collect::<std::io::Result<Vec<u16>>>()?;
        Ok(ports.windows(2).any(|pair| pair[0].abs_diff(pair[1]) > 64))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chromium_sockets_read_back_port_randomization() -> TestResult {
        let settings = chromium::v154_tcp();
        let streams = connections(settings, None, 1).await?;
        assert_eq!(random_port(&streams[0])?, sets_random_port(&settings));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn firefox_sockets_leave_port_randomization_off() -> TestResult {
        let streams = connections(firefox::v157_tcp(), None, 1).await?;
        assert!(!random_port(&streams[0])?);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_minimum_build_past_this_host_leaves_port_randomization_off() -> TestResult {
        let settings = TcpSettings {
            port_randomization: Some(TcpPortRandomization {
                minimum_windows_build: u32::MAX,
            }),
            ..chromium::v154_tcp()
        };
        let streams = connections(settings, None, 1).await?;
        assert!(!random_port(&streams[0])?);
        Ok(())
    }

    /// Whether the Chromium recipe sets the option on this host; prints a
    /// skip line naming the host's build when it does not.
    fn chromium_sets_random_port(settings: &TcpSettings) -> bool {
        if sets_random_port(settings) {
            return true;
        }
        let build = windows_port_randomization::windows_version()
            .map_or_else(|| "unknown".to_owned(), |version| version.build.to_string());
        let minimum = settings
            .port_randomization
            .map_or(0, |randomization| randomization.minimum_windows_build);
        eprintln!("skipped: Windows build {build} is below the recipe's minimum build {minimum}");
        false
    }

    /// Whether `error` says this Windows lacks the option; prints a skip line
    /// when it does.
    fn lacks_the_option(error: &std::io::Error) -> bool {
        let lacks = error.kind() == std::io::ErrorKind::Unsupported;
        if lacks {
            eprintln!("skipped: this Windows does not support SO_RANDOMIZE_PORT");
        }
        lacks
    }

    /// Windows takes the option only before a socket is bound, and the
    /// error comes back with its Winsock code.
    #[test]
    fn a_bound_socket_rejects_port_randomization() -> TestResult {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        socket.bind(&std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
        let error = match windows_port_randomization::enable(socket.as_socket()) {
            Ok(()) => return Err("a bound socket took SO_RANDOMIZE_PORT".into()),
            Err(error) => error,
        };
        if lacks_the_option(&error) {
            return Ok(());
        }
        // WSAEINVAL.
        assert_eq!(error.raw_os_error(), Some(10_022));
        assert!(!windows_port_randomization::is_enabled(socket.as_socket())?);
        Ok(())
    }

    #[test]
    fn an_unbound_socket_takes_port_randomization() -> TestResult {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        match windows_port_randomization::enable(socket.as_socket()) {
            Ok(()) => {}
            Err(error) if lacks_the_option(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        assert!(windows_port_randomization::is_enabled(socket.as_socket())?);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chromium_connections_take_scattered_local_ports() -> TestResult {
        let settings = chromium::v154_tcp();
        if !chromium_sets_random_port(&settings) {
            return Ok(());
        }
        let streams = connections(settings, None, 8).await?;
        for stream in &streams {
            assert!(random_port(stream)?);
        }
        assert!(scattered(&streams)?);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn source_bound_chromium_connections_take_scattered_local_ports() -> TestResult {
        let settings = chromium::v154_tcp();
        if !chromium_sets_random_port(&settings) {
            return Ok(());
        }
        let source = SourceBinding::new().with_address(Ipv4Addr::LOCALHOST.into());
        let streams = connections(settings, Some(&source), 8).await?;
        for stream in &streams {
            assert!(random_port(stream)?);
        }
        assert!(scattered(&streams)?);
        Ok(())
    }
}
