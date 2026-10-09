use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use super::BoxError;

#[derive(Clone, Default)]
pub(super) struct CleanupFailures {
    failures: Arc<Mutex<Vec<CleanupFailure>>>,
    #[cfg(test)]
    created: Arc<Mutex<Vec<PathBuf>>>,
}

impl CleanupFailures {
    pub(super) fn finish(&self, result: Result<(), BoxError>) -> Result<(), BoxError> {
        let failures = std::mem::take(
            &mut *self
                .failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if failures.is_empty() {
            return result;
        }
        Err(Box::new(DownloadFailure {
            primary: result.err(),
            cleanup: failures,
        }))
    }

    #[cfg(test)]
    pub(super) fn created_partial(&self) -> io::Result<PathBuf> {
        let created = self
            .created
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let [path] = created.as_slice() {
            Ok(path.clone())
        } else {
            Err(io::Error::other("expected exactly one created partial"))
        }
    }
}

pub(super) struct PartialDownload {
    directory: Option<PathBuf>,
    path: Option<PathBuf>,
    file: Option<tokio::fs::File>,
    cleanup: CleanupFailures,
}

impl PartialDownload {
    pub(super) fn create(legacy_path: PathBuf, cleanup: CleanupFailures) -> io::Result<Self> {
        // Keep the existing refusal, but never write or clean the shared name.
        match fs::symlink_metadata(&legacy_path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing existing legacy partial download",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let parent = legacy_path
            .parent()
            .ok_or_else(|| io::Error::other("partial download has no parent directory"))?;
        let directory = create_staging_directory(parent)?;

        // Record directory ownership before opening a file or reaching any await.
        let mut owner = Self {
            directory: Some(directory.clone()),
            path: None,
            file: None,
            cleanup,
        };
        let path = directory.join("download.part");
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        owner.path = Some(path.clone());
        owner.file = Some(tokio::fs::File::from_std(file));
        #[cfg(test)]
        owner
            .cleanup
            .created
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(path);

        Ok(owner)
    }

    pub(super) fn file(&mut self) -> io::Result<&mut tokio::fs::File> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("partial download already closed"))
    }

    pub(super) fn publish(&mut self, output: &Path) -> Result<(), BoxError> {
        drop(self.file.take());
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| io::Error::other("partial download already published"))?;
        // Unlike rename, hard_link never replaces an output created after the
        // initial refusal check. Staging and output are on the same filesystem.
        // The staging directory belongs exclusively to this owner. Deliberate
        // concurrent modification of its entries is outside this contract.
        fs::hard_link(path, output)?;
        fs::remove_file(path).map_err(|error| PublicationFailure {
            output: output.to_owned(),
            partial: path.clone(),
            error,
        })?;
        self.path = None;
        if let Some(directory) = &self.directory {
            fs::remove_dir(directory).map_err(|error| PublicationFailure {
                output: output.to_owned(),
                partial: directory.clone(),
                error,
            })?;
            self.directory = None;
        }
        Ok(())
    }

    fn record_cleanup_failure(&self, path: PathBuf, error: io::Error) {
        self.cleanup
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(CleanupFailure { path, error });
    }
}

impl Drop for PartialDownload {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(path) = self.path.take()
            && let Err(error) = fs::remove_file(&path)
            && error.kind() != io::ErrorKind::NotFound
        {
            self.record_cleanup_failure(path, error);
            return;
        }
        if let Some(directory) = self.directory.take()
            && let Err(error) = fs::remove_dir(&directory)
            && error.kind() != io::ErrorKind::NotFound
        {
            self.record_cleanup_failure(directory, error);
        }
    }
}

fn create_staging_directory(parent: &Path) -> io::Result<PathBuf> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();

    for _ in 0..16 {
        let mut nonce = [0_u8; 16];
        btls::rand::rand_bytes(&mut nonce).map_err(io::Error::other)?;

        let mut suffix = String::with_capacity(32);
        for byte in nonce {
            suffix.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
            suffix.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
        }
        let path = parent.join(format!(".phantom-download-{suffix}"));
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create an exclusive download staging directory",
    ))
}

#[derive(Debug)]
struct PublicationFailure {
    output: PathBuf,
    partial: PathBuf,
    error: io::Error,
}

impl fmt::Display for PublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "published download {}, but removal of partial {} failed: {}",
            self.output.display(),
            self.partial.display(),
            self.error
        )
    }
}

impl Error for PublicationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
struct CleanupFailure {
    path: PathBuf,
    error: io::Error,
}

#[derive(Debug)]
struct DownloadFailure {
    primary: Option<BoxError>,
    cleanup: Vec<CleanupFailure>,
}

impl fmt::Display for DownloadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(primary) = &self.primary {
            write!(formatter, "{primary}")?;
        } else {
            formatter.write_str("download cleanup failed")?;
        }
        for failure in &self.cleanup {
            write!(
                formatter,
                "; cleanup of {} failed: {}",
                failure.path.display(),
                failure.error
            )?;
        }
        Ok(())
    }
}

impl Error for DownloadFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.primary
            .as_ref()
            .map(|error| error.as_ref() as &(dyn Error + 'static))
            .or_else(|| {
                self.cleanup
                    .first()
                    .map(|failure| &failure.error as &(dyn Error + 'static))
            })
    }
}
