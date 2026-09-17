//! Test-only adapter for the Autobahn WebSocket client suite.

use std::{env, error::Error, io, path::PathBuf, time::Duration};

use phantom::{
    Client, PerMessageDeflate, WebSocket, WebSocketMessage, WebSocketRequestBuilder,
    profile::{ClientProfile, chromium},
};
use url::Url;

const DEFAULT_AGENT: &str = concat!("phantom/", env!("CARGO_PKG_VERSION"));
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const CASE_TIMEOUT: Duration = Duration::from_secs(15);
const DEFLATE_CASE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct Config {
    base_url: Url,
    ca_der: PathBuf,
    agent: String,
    deflate: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse(env::args().skip(1))?;
    let root = std::fs::read(&config.ca_der)?;
    let profile = ClientProfile::new(chromium::v152_macos_tls());
    let client = Client::builder(profile)
        .add_root_certificate_der(root)
        .build()?;

    let case_count = tokio::time::timeout(
        CONTROL_TIMEOUT,
        get_case_count(&client, &config.base_url, config.deflate),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "case discovery timed out"))??;
    println!("running {case_count} Autobahn cases as {}", config.agent);
    let mut timed_out_cases = Vec::new();
    for case in 1..=case_count {
        let case_timeout = if config.deflate {
            DEFLATE_CASE_TIMEOUT
        } else {
            CASE_TIMEOUT
        };
        match tokio::time::timeout(
            case_timeout,
            run_case(
                &client,
                &config.base_url,
                &config.agent,
                case,
                config.deflate,
            ),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                eprintln!("case {case}: timed out");
                timed_out_cases.push(case);
            }
        }
    }
    tokio::time::timeout(
        CONTROL_TIMEOUT,
        update_reports(&client, &config.base_url, &config.agent, config.deflate),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "report update timed out"))??;
    println!("completed {case_count} Autobahn cases");
    if !timed_out_cases.is_empty() {
        return Err(invalid_data(format!("Autobahn cases timed out: {timed_out_cases:?}")).into());
    }
    Ok(())
}

impl Config {
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let mut base_url = None;
        let mut ca_der = None;
        let mut agent = None;
        let mut deflate = false;
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            if argument == "--deflate" {
                deflate = true;
                continue;
            }
            let value = arguments
                .next()
                .ok_or_else(|| invalid_input(format!("missing value after {argument}")))?;
            match argument.as_str() {
                "--url" => base_url = Some(Url::parse(&value)?),
                "--ca-der" => ca_der = Some(PathBuf::from(value)),
                "--agent" => agent = Some(value),
                _ => return Err(invalid_input(format!("unknown argument {argument}")).into()),
            }
        }

        let base_url = base_url.ok_or_else(|| invalid_input("--url is required"))?;
        validate_base_url(&base_url)?;
        let ca_der = ca_der.ok_or_else(|| invalid_input("--ca-der is required"))?;
        if agent.as_deref() == Some("") {
            return Err(invalid_input("--agent cannot be empty").into());
        }
        Ok(Self {
            base_url,
            ca_der,
            agent: agent.unwrap_or_else(|| DEFAULT_AGENT.to_owned()),
            deflate,
        })
    }
}

async fn get_case_count(
    client: &Client,
    base_url: &Url,
    deflate: bool,
) -> Result<usize, Box<dyn Error>> {
    let url = endpoint(base_url, "/getCaseCount", &[]);
    let mut socket = websocket(client, url.as_str(), deflate)?.connect().await?;
    let mut count = None;
    loop {
        match socket.receive().await? {
            WebSocketMessage::Text(value) => {
                if count.is_some() {
                    return Err(invalid_data("Autobahn returned more than one case count").into());
                }
                count = Some(value.parse()?);
            }
            WebSocketMessage::Close(_) => break,
            WebSocketMessage::Binary(_) | WebSocketMessage::Ping(_) | WebSocketMessage::Pong(_) => {
                return Err(invalid_data("Autobahn returned an invalid case-count message").into());
            }
            _ => {
                return Err(invalid_data("Autobahn returned an unknown case-count message").into());
            }
        }
    }
    count.ok_or_else(|| invalid_data("Autobahn omitted the case count").into())
}

async fn run_case(
    client: &Client,
    base_url: &Url,
    agent: &str,
    case: usize,
    deflate: bool,
) -> Result<(), Box<dyn Error>> {
    let case_string = case.to_string();
    let url = endpoint(
        base_url,
        "/runCase",
        &[("case", &case_string), ("agent", agent)],
    );
    let mut socket = websocket(client, url.as_str(), deflate)?.connect().await?;
    loop {
        match socket.receive().await {
            Ok(WebSocketMessage::Text(value)) => {
                socket.send(WebSocketMessage::Text(value)).await?;
            }
            Ok(WebSocketMessage::Binary(value)) => {
                socket.send(WebSocketMessage::Binary(value)).await?;
            }
            Ok(WebSocketMessage::Ping(_) | WebSocketMessage::Pong(_)) => {}
            Ok(WebSocketMessage::Close(_)) => break,
            Err(error) => {
                eprintln!("case {case}: connection ended with {:?}", error.kind());
                break;
            }
            Ok(_) => return Err(invalid_data("Autobahn returned an unknown message type").into()),
        }
    }
    Ok(())
}

async fn update_reports(
    client: &Client,
    base_url: &Url,
    agent: &str,
    deflate: bool,
) -> Result<(), Box<dyn Error>> {
    let url = endpoint(base_url, "/updateReports", &[("agent", agent)]);
    let mut socket = websocket(client, url.as_str(), deflate)?.connect().await?;
    wait_for_close(&mut socket).await
}

fn websocket(
    client: &Client,
    url: &str,
    deflate: bool,
) -> Result<WebSocketRequestBuilder, phantom::WebSocketError> {
    let builder = client.websocket(url)?;
    Ok(if deflate {
        builder.permessage_deflate(PerMessageDeflate::new())
    } else {
        builder
    })
}

async fn wait_for_close(socket: &mut WebSocket) -> Result<(), Box<dyn Error>> {
    loop {
        match socket.receive().await? {
            WebSocketMessage::Close(_) => return Ok(()),
            WebSocketMessage::Ping(_) | WebSocketMessage::Pong(_) => {}
            WebSocketMessage::Text(_) | WebSocketMessage::Binary(_) => {
                return Err(invalid_data("Autobahn returned unexpected report data").into());
            }
            _ => return Err(invalid_data("Autobahn returned an unknown report message").into()),
        }
    }
}

fn endpoint(base_url: &Url, path: &str, query: &[(&str, &str)]) -> Url {
    let mut url = base_url.clone();
    url.set_path(path);
    url.set_query(None);
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query.iter().copied());
    }
    url
}

fn validate_base_url(url: &Url) -> Result<(), io::Error> {
    if url.scheme() != "wss" {
        return Err(invalid_input("--url must use wss"));
    }
    if url.cannot_be_a_base() || url.host_str().is_none() {
        return Err(invalid_input("--url must contain a host"));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid_input(
            "--url must not contain a path, query, or fragment",
        ));
    }
    Ok(())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::{Config, endpoint};

    #[test]
    fn endpoint_replaces_control_path_and_encodes_query() -> Result<(), Box<dyn std::error::Error>>
    {
        let base = url::Url::parse("wss://localhost:9001/")?;
        let url = endpoint(
            &base,
            "/runCase",
            &[("case", "7"), ("agent", "phantom test/0.1")],
        );

        assert_eq!(
            url.as_str(),
            "wss://localhost:9001/runCase?case=7&agent=phantom+test%2F0.1"
        );
        Ok(())
    }

    #[test]
    fn config_requires_a_root_wss_url() {
        let error = Config::parse([
            "--url".into(),
            "ws://localhost:9001/path".into(),
            "--ca-der".into(),
            "root.der".into(),
        ])
        .expect_err("plain WebSocket must be rejected");

        assert!(error.to_string().contains("must use wss"));
    }
}
