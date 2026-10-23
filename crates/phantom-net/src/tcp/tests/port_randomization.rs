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
    use std::{io, net::Ipv4Addr, os::windows::io::AsSocket};

    use phantom_profile::{
        TcpPortRandomization, TcpSettings,
        browser::{chrome, firefox},
    };
    use tokio::net::TcpListener;

    use super::super::TestResult;
    use crate::{
        SourceBinding,
        socket_ffi::port_randomization,
        tcp::{ProfileTcpStream, connect, host_reaches_build},
    };

    enum Observation {
        Exercised(&'static str),
        Unavailable,
        NotApplicable,
    }

    fn observe(test: &'static str, observation: Observation) {
        let (status, reason) = match observation {
            Observation::Exercised(reason) => ("exercised", reason),
            Observation::Unavailable => ("unavailable", "socket_option_unsupported"),
            Observation::NotApplicable => ("not_applicable", "host_below_profile_minimum"),
        };
        eprintln!(
            r#"{{"capability":"tcp_port_randomization","test":"{test}","status":"{status}","reason":"{reason}"}}"#
        );
    }

    fn recipe_applies(settings: &TcpSettings) -> io::Result<bool> {
        settings
            .port_randomization
            .map_or(Ok(false), |randomization| {
                host_reaches_build(randomization.minimum_windows_build)
            })
    }

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
        Ok(port_randomization::is_enabled(stream.as_socket())?)
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
        let settings = chrome::v154_tcp();
        let applies = recipe_applies(&settings)?;
        let streams = connections(settings, None, 1).await?;
        assert_eq!(random_port(&streams[0])?, applies);
        observe(
            "chromium_sockets_read_back_port_randomization",
            if applies {
                Observation::Exercised("profile_socket_option_read_back")
            } else {
                Observation::NotApplicable
            },
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn firefox_sockets_leave_port_randomization_off() -> TestResult {
        let streams = connections(firefox::v157_tcp(), None, 1).await?;
        assert!(!random_port(&streams[0])?);
        observe(
            "firefox_sockets_leave_port_randomization_off",
            Observation::Exercised("disabled_profile_socket_option_read_back"),
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_minimum_build_past_this_host_leaves_port_randomization_off() -> TestResult {
        let settings = TcpSettings {
            port_randomization: Some(TcpPortRandomization {
                minimum_windows_build: u32::MAX,
            }),
            ..chrome::v154_tcp()
        };
        let streams = connections(settings, None, 1).await?;
        assert!(!random_port(&streams[0])?);
        observe(
            "a_minimum_build_past_this_host_leaves_port_randomization_off",
            Observation::Exercised("above_host_minimum_leaves_option_disabled"),
        );
        Ok(())
    }

    fn lacks_the_option(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::Unsupported
    }

    #[test]
    fn only_unsupported_means_the_socket_option_is_unavailable() {
        assert!(lacks_the_option(&io::Error::from(
            io::ErrorKind::Unsupported
        )));
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::Other,
        ] {
            assert!(!lacks_the_option(&io::Error::from(kind)));
        }
    }

    /// Windows takes the option only before a socket is bound, and the
    /// error comes back with its Winsock code.
    #[test]
    fn a_bound_socket_rejects_port_randomization() -> TestResult {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        socket.bind(&std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
        let error = match port_randomization::enable(socket.as_socket()) {
            Ok(()) => return Err("a bound socket took SO_RANDOMIZE_PORT".into()),
            Err(error) => error,
        };
        if lacks_the_option(&error) {
            observe(
                "a_bound_socket_rejects_port_randomization",
                Observation::Unavailable,
            );
            return Ok(());
        }
        // WSAEINVAL.
        assert_eq!(error.raw_os_error(), Some(10_022));
        assert!(!port_randomization::is_enabled(socket.as_socket())?);
        observe(
            "a_bound_socket_rejects_port_randomization",
            Observation::Exercised("bound_socket_rejected_and_option_disabled"),
        );
        Ok(())
    }

    #[test]
    fn an_unbound_socket_takes_port_randomization() -> TestResult {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        match port_randomization::enable(socket.as_socket()) {
            Ok(()) => {}
            Err(error) if lacks_the_option(&error) => {
                observe(
                    "an_unbound_socket_takes_port_randomization",
                    Observation::Unavailable,
                );
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        assert!(port_randomization::is_enabled(socket.as_socket())?);
        observe(
            "an_unbound_socket_takes_port_randomization",
            Observation::Exercised("unbound_socket_option_read_back"),
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chromium_connections_take_scattered_local_ports() -> TestResult {
        let settings = chrome::v154_tcp();
        if !recipe_applies(&settings)? {
            observe(
                "chromium_connections_take_scattered_local_ports",
                Observation::NotApplicable,
            );
            return Ok(());
        }
        let streams = connections(settings, None, 8).await?;
        for stream in &streams {
            assert!(random_port(stream)?);
        }
        assert!(scattered(&streams)?);
        observe(
            "chromium_connections_take_scattered_local_ports",
            Observation::Exercised("connected_ports_scattered_and_option_enabled"),
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn source_bound_chromium_connections_take_scattered_local_ports() -> TestResult {
        let settings = chrome::v154_tcp();
        if !recipe_applies(&settings)? {
            observe(
                "source_bound_chromium_connections_take_scattered_local_ports",
                Observation::NotApplicable,
            );
            return Ok(());
        }
        let source = SourceBinding::new().with_address(Ipv4Addr::LOCALHOST.into());
        let streams = connections(settings, Some(&source), 8).await?;
        for stream in &streams {
            assert!(random_port(stream)?);
        }
        assert!(scattered(&streams)?);
        observe(
            "source_bound_chromium_connections_take_scattered_local_ports",
            Observation::Exercised("source_bound_ports_scattered_and_option_enabled"),
        );
        Ok(())
    }
}
