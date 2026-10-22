//! Explicit offline installation and digest-pinned selection.

use std::{io, path::Path};

use clap::ArgMatches;
use phantom::fingerprint::ProfileBundle;
use phantom_profile::ClientProfile;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{CliError, Result};

use super::{MAX_PROFILE_BYTES, required, write_output};

async fn read(path: &Path) -> Result<(ProfileBundle, Vec<u8>)> {
    if !tokio::fs::metadata(path).await?.is_file() {
        return Err(CliError::invalid("bundle must be a regular file"));
    }
    let file = tokio::fs::File::open(path).await?;
    if !file.metadata().await?.is_file() {
        return Err(CliError::invalid("bundle must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take((MAX_PROFILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    let bundle = ProfileBundle::from_json(&bytes).map_err(CliError::operation)?;
    Ok((bundle, bytes))
}

fn digest(value: &str) -> Result<&str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::invalid(
            "bundle digest must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    Ok(value)
}

pub(crate) async fn select(arguments: &ArgMatches) -> Result<ClientProfile> {
    let digest = digest(required(arguments, "bundle")?)?;
    let store = arguments
        .get_one::<std::path::PathBuf>("bundle-store")
        .ok_or_else(|| CliError::invalid("missing bundle store"))?;
    let (bundle, _) = read(&store.join(digest)).await?;
    if bundle.sha256() != digest {
        return Err(CliError::operation(
            "installed bundle content does not match its pinned digest",
        ));
    }
    bundle
        .profiles()
        .get(required(arguments, "bundle-profile")?)
        .cloned()
        .ok_or_else(|| CliError::invalid("exact bundle profile name was not found"))
}

pub(super) async fn run(arguments: &ArgMatches) -> Result<()> {
    let (operation, arguments) = arguments
        .subcommand()
        .ok_or_else(|| CliError::invalid("missing bundle operation"))?;
    let path = arguments
        .get_one::<std::path::PathBuf>("file")
        .ok_or_else(|| CliError::invalid("missing bundle file"))?;
    let (bundle, bytes) = read(path).await?;
    if operation == "inspect" {
        let profiles = bundle.profiles().names().map(|name| {
            let provenance: Vec<_> = bundle.provenance(name).unwrap_or_default().iter()
                .map(|reference| json!({"source": reference.source(), "revision": reference.revision()})).collect();
            json!({"name": name, "provenance": provenance})
        }).collect::<Vec<_>>();
        let document = json!({"id": bundle.id(), "revision": bundle.revision(), "sha256": bundle.sha256(), "profiles": profiles,
            "note": "References are supplied by the publisher; bundles are not signed."});
        return write_output(
            None,
            &serde_json::to_vec_pretty(&document).map_err(CliError::operation)?,
        )
        .await;
    }
    let store = arguments
        .get_one::<std::path::PathBuf>("store")
        .ok_or_else(|| CliError::invalid("missing bundle store"))?;
    let destination = store.join(bundle.sha256());
    let opened = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .await;
    match opened {
        Ok(mut file) => {
            let result = async {
                file.write_all(&bytes).await?;
                file.flush().await
            }
            .await;
            drop(file);
            if let Err(original) = result {
                if let Err(cleanup) = tokio::fs::remove_file(&destination).await {
                    return Err(CliError::operation(format!(
                        "bundle write failed: {original}; incomplete-file cleanup failed: {cleanup}"
                    )));
                }
                return Err(original.into());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let (existing, existing_bytes) = read(&destination).await?;
            if existing.sha256() != bundle.sha256() || existing_bytes != bytes {
                return Err(CliError::operation(
                    "installed bundle conflicts with its digest filename",
                ));
            }
        }
        Err(error) => return Err(error.into()),
    }
    write_output(None, format!("{}\n", bundle.sha256()).as_bytes()).await
}
