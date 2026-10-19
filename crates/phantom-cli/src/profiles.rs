use std::path::{Path, PathBuf};

use clap::ArgMatches;
use phantom::fingerprint::{describe_profile, export_profile_json, import_profile_json};
use phantom_profile::{ClientProfile, catalog};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{CliError, Result};

pub(super) const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn required<'a>(arguments: &'a ArgMatches, name: &str) -> Result<&'a str> {
    arguments
        .get_one::<String>(name)
        .map(String::as_str)
        .ok_or_else(|| CliError::invalid(format!("missing {name}")))
}

pub(super) async fn read_profile(path: &Path) -> Result<ClientProfile> {
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take((MAX_PROFILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(CliError::invalid("profile file exceeds 16 MiB"));
    }
    import_profile_json(&bytes).map_err(CliError::operation)
}

pub(super) async fn write_output(path: Option<&PathBuf>, bytes: &[u8]) -> Result<()> {
    if let Some(path) = path {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await?;
        file.write_all(bytes).await?;
        file.flush().await?;
    } else {
        let mut stdout = tokio::io::stdout();
        stdout.write_all(bytes).await?;
        stdout.flush().await?;
    }
    Ok(())
}

pub(super) async fn run(arguments: &ArgMatches) -> Result<()> {
    let (operation, arguments) = arguments
        .subcommand()
        .ok_or_else(|| CliError::invalid("missing profile operation"))?;
    match operation {
        "list" => {
            let mut stdout = tokio::io::stdout();
            for definition in catalog::profiles() {
                stdout
                    .write_all(definition.id().as_str().as_bytes())
                    .await?;
                stdout.write_all(b"\n").await?;
            }
            stdout.flush().await?;
            Ok(())
        }
        "describe" | "export" => {
            let definition =
                catalog::profile(required(arguments, "id")?).map_err(CliError::operation)?;
            let profile = definition.instantiate(&[]).map_err(CliError::operation)?;
            if operation == "export" {
                return write_output(
                    arguments.get_one::<PathBuf>("output"),
                    &export_profile_json(&profile).map_err(CliError::operation)?,
                )
                .await;
            }
            let metadata = definition.metadata();
            let document = json!({
                "id": definition.id().as_str(), "browser_build": metadata.build(),
                "platform_release": metadata.platform_release(), "architecture": metadata.architecture(),
                "revision": metadata.revision(),
                "settings": describe_profile(&profile).map_err(CliError::operation)?,
                "note": "Catalog metadata does not establish fidelity for every setting; exported settings carry no browser identity."
            });
            write_output(
                None,
                &serde_json::to_vec_pretty(&document).map_err(CliError::operation)?,
            )
            .await
        }
        "import" => {
            let path = arguments
                .get_one::<PathBuf>("file")
                .ok_or_else(|| CliError::invalid("missing profile file"))?;
            let profile = read_profile(path).await?;
            write_output(
                arguments.get_one::<PathBuf>("output"),
                &export_profile_json(&profile).map_err(CliError::operation)?,
            )
            .await
        }
        _ => Err(CliError::invalid("unknown profile operation")),
    }
}
