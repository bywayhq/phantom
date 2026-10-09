use std::fmt;

use http::Uri;

use crate::{BuildError, RequestError, authority::parse_absolute_uri};

#[derive(Clone)]
pub(crate) struct BaseUrl(url::Url);

impl BaseUrl {
    pub(crate) fn new(value: &str) -> Result<Self, BuildError> {
        let uri = parse_absolute_uri(value).map_err(BuildError::invalid_base_url)?;
        let port = match uri.scheme_str() {
            Some("http") => 80,
            Some("https") => 443,
            _ => {
                return Err(BuildError::invalid_base_url(
                    url::ParseError::RelativeUrlWithoutBase,
                ));
            }
        };
        let authority = uri
            .authority()
            .cloned()
            .ok_or_else(|| BuildError::invalid_base_url(url::ParseError::EmptyHost))?;
        crate::authority::Endpoint::new(authority, port).map_err(BuildError::invalid_base_url)?;
        url::Url::parse(&uri.to_string())
            .map(Self)
            .map_err(BuildError::invalid_base_url)
    }

    pub(crate) fn resolve(&self, value: &str) -> Result<Uri, RequestError> {
        // Absolute requests retain the existing target bytes, including dot segments.
        if value.split_once(':').is_some_and(|(scheme, _)| {
            scheme.starts_with(|character: char| character.is_ascii_alphabetic())
                && scheme
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
        }) {
            return parse_absolute_uri(value).map_err(super::request::request_uri_error);
        }
        if value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
            || value.contains('\\')
        {
            return Err(RequestError::invalid_url(
                url::ParseError::InvalidDomainCharacter,
            ));
        }
        let joined = self.0.join(value).map_err(RequestError::invalid_url)?;
        parse_absolute_uri(joined.as_str()).map_err(super::request::request_uri_error)
    }
}

impl fmt::Debug for BaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BaseUrl { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::BaseUrl;

    #[test]
    fn joins_paths_queries_and_cross_origin_references() -> Result<(), Box<dyn std::error::Error>> {
        let base = BaseUrl::new("https://example.test/api/?old=1")?;
        for (reference, expected) in [
            ("users", "https://example.test/api/users"),
            ("../users", "https://example.test/users"),
            ("/users", "https://example.test/users"),
            ("?next=2", "https://example.test/api/?next=2"),
            ("", "https://example.test/api/?old=1"),
            ("//other.test/path", "https://other.test/path"),
            (
                "https://other.test/a/%2e%2e/b?x=%2f",
                "https://other.test/a/%2e%2e/b?x=%2f",
            ),
            (
                "nested/http://text",
                "https://example.test/api/nested/http://text",
            ),
        ] {
            assert_eq!(base.resolve(reference)?.to_string(), expected);
        }
        assert_eq!(
            BaseUrl::new("https://example.test/api")?
                .resolve("users")?
                .path(),
            "/users"
        );
        Ok(())
    }

    #[test]
    fn invalid_configuration_and_ambiguous_references_are_recoverable()
    -> Result<(), Box<dyn std::error::Error>> {
        for value in [
            "/api/",
            "ftp://example.test/",
            "https://user:secret@example.test/",
            "https://example.test/#part",
            "https://example.test:0/",
            "https://example.test:65536/",
        ] {
            assert!(BaseUrl::new(value).is_err(), "{value}");
        }
        let base = BaseUrl::new("https://example.test/private?secret=canary")?;
        assert!(!format!("{base:?}").contains("canary"));
        for reference in [
            "#part",
            "//user:secret@other.test/",
            "\\\\other.test/path",
            "users\n",
            " users",
        ] {
            assert!(base.resolve(reference).is_err(), "{reference}");
        }
        Ok(())
    }
}
