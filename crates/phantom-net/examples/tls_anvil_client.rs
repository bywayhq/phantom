//! One-connection adapter for TLS-Anvil client-mode tests.

use std::{env, error::Error, io, time::Duration};

use phantom_net::{ServerAuthentication, http1::Http1TlsConnector};
use phantom_profile::chromium;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct Config {
    host: String,
    port: u16,
    server_name: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse(env::args().skip(1))?;
    let mut settings = chromium::v152_macos_tls();
    settings.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    settings.alps = None;
    let connector = Http1TlsConnector::new_with_server_authentication(
        &settings,
        ServerAuthentication::Disabled,
    )?;

    let connection = tokio::time::timeout(
        CONNECTION_TIMEOUT,
        connector.connect_direct(&config.host, config.port, &config.server_name),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS connection timed out"))??;
    drop(connection);
    Ok(())
}

impl Config {
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let mut host = None;
        let mut port = None;
        let mut server_name = None;
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| invalid_input(format!("missing value after {argument}")))?;
            match argument.as_str() {
                "--host" => host = Some(value),
                "--port" => port = Some(value.parse()?),
                "--server-name" => server_name = Some(value),
                _ => return Err(invalid_input(format!("unknown argument {argument}")).into()),
            }
        }

        let host = required_nonempty(host, "--host")?;
        let port = port.ok_or_else(|| invalid_input("--port is required"))?;
        let server_name = required_nonempty(server_name, "--server-name")?;
        Ok(Self {
            host,
            port,
            server_name,
        })
    }
}

fn required_nonempty(value: Option<String>, name: &str) -> Result<String, io::Error> {
    match value {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(invalid_input(format!("{name} cannot be empty"))),
        None => Err(invalid_input(format!("{name} is required"))),
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn parses_complete_target() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::parse([
            "--host".into(),
            "127.0.0.1".into(),
            "--port".into(),
            "8443".into(),
            "--server-name".into(),
            "localhost".into(),
        ])?;

        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8443);
        assert_eq!(config.server_name, "localhost");
        Ok(())
    }

    #[test]
    fn rejects_missing_and_unknown_arguments() {
        assert!(Config::parse(Vec::<String>::new()).is_err());
        assert!(Config::parse(["--unknown".into(), "value".into()]).is_err());
    }
}
