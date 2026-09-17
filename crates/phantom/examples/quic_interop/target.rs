use std::fmt;

use url::Url;

const ALLOWED_HOSTS: [&str; 4] = ["server", "server4", "server6", "server46"];

pub(super) struct DownloadTarget {
    url: Url,
    file_name: String,
}

impl DownloadTarget {
    pub(super) fn parse(value: &str) -> Result<Self, InvalidTarget> {
        let url = Url::parse(value).map_err(|_| InvalidTarget::new("invalid URL"))?;
        if url.scheme() != "https" {
            return Err(InvalidTarget::new("URL scheme must be https"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(InvalidTarget::new("URL credentials are not allowed"));
        }
        if !matches!(url.host_str(), Some(host) if ALLOWED_HOSTS.contains(&host)) {
            return Err(InvalidTarget::new("URL host is not a runner server"));
        }
        if !matches!(url.port(), None | Some(443)) {
            return Err(InvalidTarget::new("URL port must be 443"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(InvalidTarget::new("URL query and fragment are not allowed"));
        }

        let segments = url
            .path_segments()
            .ok_or_else(|| InvalidTarget::new("URL path cannot name a file"))?
            .collect::<Vec<_>>();
        if segments.len() != 1 || !valid_file_name(segments[0]) {
            return Err(InvalidTarget::new("URL must contain one safe file name"));
        }

        Ok(Self {
            file_name: segments[0].to_owned(),
            url,
        })
    }

    pub(super) fn url(&self) -> &Url {
        &self.url
    }

    pub(super) fn file_name(&self) -> &str {
        &self.file_name
    }

    pub(super) fn same_origin(&self, other: &Self) -> bool {
        self.url.origin() == other.url.origin()
    }
}

fn valid_file_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub(super) struct InvalidTarget {
    message: &'static str,
}

impl InvalidTarget {
    const fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Debug for InvalidTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvalidTarget")
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for InvalidTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for InvalidTarget {}

#[cfg(test)]
mod tests {
    use super::DownloadTarget;

    #[test]
    fn accepts_runner_hosts_and_safe_root_files() -> Result<(), Box<dyn std::error::Error>> {
        for value in [
            "https://server/file",
            "https://server4:443/a-b_c.txt",
            "https://server6/file",
            "https://server46/file",
        ] {
            DownloadTarget::parse(value)?;
        }
        Ok(())
    }

    #[test]
    fn rejects_urls_outside_the_runner_contract() {
        for value in [
            "http://server/file",
            "https://example.com/file",
            "https://user@server/file",
            "https://server:444/file",
            "https://server/dir/file",
            "https://server/file?query",
            "https://server/file#fragment",
            "https://server/%2e%2e",
            "https://server/file%20name",
        ] {
            assert!(DownloadTarget::parse(value).is_err(), "{value}");
        }
    }
}
