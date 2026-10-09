use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use super::BoxError;

#[derive(Clone, Default)]
pub(super) struct CleanupFailures(Arc<Mutex<Vec<CleanupFailure>>>);

impl CleanupFailures {
    pub(super) fn finish(&self, result: Result<(), BoxError>) -> Result<(), BoxError> {
        let failures = std::mem::take(
            &mut *self
                .0
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
}

pub(super) struct PartialDownload {
    path: Option<PathBuf>,
    file: Option<tokio::fs::File>,
    cleanup: CleanupFailures,
}

impl PartialDownload {
    pub(super) fn create(path: PathBuf, cleanup: CleanupFailures) -> io::Result<Self> {
        // There is no cancellation point between exclusive creation and
        // recording ownership. An async open can finish after its future drops.
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        Ok(Self {
            path: Some(path),
            file: Some(tokio::fs::File::from_std(file)),
            cleanup,
        })
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
        // initial refusal check. Both names are in the same directory.
        fs::hard_link(path, output)?;
        fs::remove_file(path).map_err(|error| PublicationFailure {
            output: output.to_owned(),
            partial: path.clone(),
            error,
        })?;
        self.path = None;
        Ok(())
    }
}

impl Drop for PartialDownload {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(path) = self.path.take()
            && let Err(error) = fs::remove_file(&path)
            && error.kind() != io::ErrorKind::NotFound
        {
            self.cleanup
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(CleanupFailure { path, error });
        }
    }
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
