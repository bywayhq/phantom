//! Client endpoint for the QUIC Interop Runner's HTTP/3 case.

use std::{
    collections::HashSet,
    env,
    error::Error,
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use btls::x509::X509;
use phantom::{
    Client, HttpProtocol, ResponseInfo,
    profile::{ClientProfile, Http3ClientSettings, browser::chrome},
};
use tokio::{fs, io::AsyncWriteExt, task::JoinSet, time::timeout};

mod partial_download;
mod target;

use partial_download::{CleanupFailures, PartialDownload};
use target::DownloadTarget;

const SUPPORTED_CASE: &str = "http3";
const UNSUPPORTED_EXIT_CODE: u8 = 127;
const MAX_REQUESTS: usize = 64;
const MAX_DOWNLOAD_BYTES: usize = 16 * 1024 * 1024;
const DOWNLOAD_BATCH_TIMEOUT: Duration = Duration::from_secs(45);

type BoxError = Box<dyn Error + Send + Sync>;

enum Invocation {
    Unsupported,
    Run(Config),
}

enum InvocationOutcome {
    Complete,
    Unsupported,
}

struct Config {
    ca_pem: PathBuf,
    download_directory: PathBuf,
    targets: Vec<DownloadTarget>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(InvocationOutcome::Complete) => ExitCode::SUCCESS,
        Ok(InvocationOutcome::Unsupported) => ExitCode::from(UNSUPPORTED_EXIT_CODE),
        Err(error) => {
            eprintln!(
                "phantom QUIC interop client: {}",
                one_line(&error.to_string())
            );
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<InvocationOutcome, BoxError> {
    let Invocation::Run(config) = Config::from_environment()? else {
        return Ok(InvocationOutcome::Unsupported);
    };
    let client = build_client(&config.ca_pem).await?;
    fs::create_dir_all(&config.download_directory).await?;
    download_all(client, config).await?;
    Ok(InvocationOutcome::Complete)
}

impl Config {
    fn from_environment() -> Result<Invocation, BoxError> {
        if required_environment("ROLE")? != "client" {
            return Err(invalid_input("ROLE must be client").into());
        }
        let test_case = required_environment("TESTCASE")?;
        if test_case != SUPPORTED_CASE {
            return Ok(Invocation::Unsupported);
        }

        let requests = required_environment("REQUESTS")?;
        let ca_pem = optional_path("PHANTOM_INTEROP_CA_PEM", "/certs/ca.pem")?;
        let download_directory = optional_path("PHANTOM_INTEROP_DOWNLOADS", "/downloads")?;
        Self::parse(&requests, ca_pem, download_directory).map(Invocation::Run)
    }

    fn parse(
        requests: &str,
        ca_pem: PathBuf,
        download_directory: PathBuf,
    ) -> Result<Self, BoxError> {
        let request_values = requests.split_ascii_whitespace().collect::<Vec<_>>();
        if request_values.is_empty() {
            return Err(invalid_input("REQUESTS must contain at least one URL").into());
        }
        if request_values.len() > MAX_REQUESTS {
            return Err(
                invalid_input(format!("REQUESTS exceeds the {MAX_REQUESTS}-URL bound")).into(),
            );
        }

        let targets = request_values
            .into_iter()
            .map(DownloadTarget::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let (first, remaining) = targets
            .split_first()
            .ok_or_else(|| invalid_input("REQUESTS must contain at least one URL"))?;
        if remaining.iter().any(|target| !target.same_origin(first)) {
            return Err(invalid_input("all REQUESTS URLs must share one origin").into());
        }

        let mut names = HashSet::with_capacity(targets.len());
        if targets
            .iter()
            .any(|target| !names.insert(target.file_name()))
        {
            return Err(invalid_input("REQUESTS contains duplicate output names").into());
        }

        Ok(Self {
            ca_pem,
            download_directory,
            targets,
        })
    }
}

async fn build_client(ca_pem: &Path) -> Result<Client, BoxError> {
    let pem = fs::read(ca_pem).await?;
    let mut roots = X509::stack_from_pem(&pem)?;
    if roots.len() != 1 {
        return Err(invalid_input("interop CA file must contain exactly one certificate").into());
    }
    let root = roots
        .pop()
        .ok_or_else(|| invalid_input("interop CA file is empty"))?
        .to_der()?;

    let http3_tls = chrome::v154_quic_tls();
    let http3 = Http3ClientSettings::new(
        http3_tls.clone(),
        chrome::v154_quic(),
        chrome::v154_http3(),
        chrome::v154_http3_request(),
    );
    let profile = ClientProfile::new(http3_tls).with_http3(http3);
    Ok(Client::builder(profile)
        .add_root_certificate_der(root)
        .build()?)
}

async fn download_all(client: Client, config: Config) -> Result<(), BoxError> {
    download_all_with_cleanup(client, config, CleanupFailures::default()).await
}

async fn download_all_with_cleanup(
    client: Client,
    config: Config,
    cleanup: CleanupFailures,
) -> Result<(), BoxError> {
    let mut downloads = JoinSet::new();
    for target in config.targets {
        downloads.spawn(download_one_owned(
            client.clone(),
            config.download_directory.clone(),
            target,
            cleanup.clone(),
        ));
    }

    let result = match timeout(DOWNLOAD_BATCH_TIMEOUT, async {
        while let Some(joined) = downloads.join_next().await {
            match joined {
                Ok(result) => result?,
                Err(error) => return Err(Box::new(io::Error::other(error)) as BoxError),
            }
        }
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(invalid_data("download batch timed out").into()),
    };

    if result.is_err() {
        downloads.abort_all();
        while downloads.join_next().await.is_some() {}
    }
    cleanup.finish(result)
}

#[cfg(test)]
async fn download_one(
    client: Client,
    directory: PathBuf,
    target: DownloadTarget,
) -> Result<(), BoxError> {
    let cleanup = CleanupFailures::default();
    let result = download_one_owned(client, directory, target, cleanup.clone()).await;
    cleanup.finish(result)
}

async fn download_one_owned(
    client: Client,
    directory: PathBuf,
    target: DownloadTarget,
    cleanup: CleanupFailures,
) -> Result<(), BoxError> {
    let output = directory.join(target.file_name());
    if fs::try_exists(&output).await? {
        return Err(invalid_data(format!(
            "refusing to replace existing download {}",
            output.display()
        ))
        .into());
    }

    let mut partial = PartialDownload::create(
        directory.join(format!(".{}.part", target.file_name())),
        cleanup,
    )?;
    download_to_partial(&client, &target, partial.file()?).await?;
    partial.publish(&output)?;
    Ok(())
}

async fn download_to_partial(
    client: &Client,
    target: &DownloadTarget,
    file: &mut tokio::fs::File,
) -> Result<(), BoxError> {
    use http_body_util::BodyExt as _;

    let response = client
        .get(HttpProtocol::Http3, target.url().as_str())?
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(invalid_data(format!(
            "{} returned HTTP {}",
            target.url(),
            response.status()
        ))
        .into());
    }
    let protocol = response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol);
    if protocol != Some(HttpProtocol::Http3) {
        return Err(invalid_data("download did not use HTTP/3").into());
    }

    let mut received = 0usize;
    let mut body = response.into_body();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            received = received
                .checked_add(data.len())
                .ok_or_else(|| invalid_data("download size overflowed"))?;
            if received > MAX_DOWNLOAD_BYTES {
                return Err(invalid_data(format!(
                    "download exceeded the {MAX_DOWNLOAD_BYTES}-byte bound"
                ))
                .into());
            }
            file.write_all(&data).await?;
        }
    }
    file.flush().await?;
    Ok(())
}

fn required_environment(name: &str) -> Result<String, BoxError> {
    let value = env::var_os(name).ok_or_else(|| invalid_input(format!("{name} is required")))?;
    value
        .into_string()
        .map_err(|_: OsString| invalid_input(format!("{name} must be valid UTF-8")).into())
}

fn optional_path(name: &str, default: &str) -> Result<PathBuf, BoxError> {
    match env::var_os(name) {
        Some(value) if value.is_empty() => {
            Err(invalid_input(format!("{name} must not be empty")).into())
        }
        Some(value) => Ok(PathBuf::from(value)),
        None => Ok(PathBuf::from(default)),
    }
}

fn one_line(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\n' | '\r' | '\t' => ' ',
            other => other,
        })
        .take(500)
        .collect()
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests;
