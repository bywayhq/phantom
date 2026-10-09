//! Customize ordered caller headers before request validation.

use std::{error::Error, fmt, sync::Arc};

use http::{
    Method, Uri,
    header::{HeaderName, HeaderValue},
};

use crate::RequestHeader;

/// The initial request and its ordered caller headers, before template expansion.
///
/// Client hooks run in registration order, then request hooks. They run once
/// when sending begins, after prepared-body headers and before network I/O.
/// Retries reuse the result. Hooks do not rerun on redirects. Cross-origin
/// redirects remove `Authorization`, `Cookie`, `Cookie2`, and
/// `Proxy-Authorization`. Custom credential fields remain, even when sensitive.
/// Check [`Self::uri`] before adding credentials. For custom credentials, disable
/// automatic redirects and check each new request's origin yourself.
/// Generated headers, cookies, hints, and template literals are added afterward.
/// This is not the complete wire header list. Hooks do not receive the body.
///
/// Hooks are synchronous: avoid blocking or doing network I/O in them.
pub struct HeaderHookContext<'a> {
    pub(crate) method: &'a Method,
    pub(crate) uri: &'a Uri,
    pub(crate) headers: &'a mut Vec<RequestHeader>,
    pub(crate) protected: &'static [&'static str],
}

impl HeaderHookContext<'_> {
    /// Returns the initial request method.
    #[must_use]
    pub fn method(&self) -> &Method {
        self.method
    }

    /// Returns the resolved initial URI, including its path and query.
    ///
    /// It may contain secrets. The context's Debug output omits it.
    #[must_use]
    pub fn uri(&self) -> &Uri {
        self.uri
    }

    /// Returns the ordered caller headers, including earlier hook changes.
    #[must_use]
    pub fn headers(&self) -> &[RequestHeader] {
        self.headers
    }

    /// Appends a header after the current caller headers, keeping duplicates.
    ///
    /// # Errors
    /// Invalid HTTP names or values, or a managed SSE `Last-Event-ID` field,
    /// fail without changing any headers.
    pub fn append(&mut self, header: RequestHeader) -> Result<(), HeaderHookError> {
        self.check_name(header.name())?;
        validate(&header)?;
        self.headers.push(header);
        Ok(())
    }

    /// Replaces this name at its first position and removes later duplicates.
    ///
    /// Name comparison ignores ASCII case. A new name is appended. Templates
    /// still supply matching headers' position and spelling during expansion.
    ///
    /// # Errors
    /// Invalid HTTP names or values, or a managed SSE `Last-Event-ID` field,
    /// fail without changing any headers.
    pub fn set(&mut self, header: RequestHeader) -> Result<(), HeaderHookError> {
        self.check_name(header.name())?;
        validate(&header)?;
        if let Some(index) = self
            .headers
            .iter()
            .position(|old| old.name().eq_ignore_ascii_case(header.name()))
        {
            let name = header.name().to_owned();
            self.headers[index] = header;
            let mut position = 0;
            self.headers.retain(|old| {
                let keep = position <= index || !old.name().eq_ignore_ascii_case(&name);
                position += 1;
                keep
            });
        } else {
            self.headers.push(header);
        }
        Ok(())
    }

    /// Removes all caller headers with this name, ignoring ASCII case.
    ///
    /// Removing a caller override may reveal a template literal afterward.
    ///
    /// # Errors
    /// Returns an error for a managed SSE `Last-Event-ID` field.
    pub fn remove(&mut self, name: &str) -> Result<(), HeaderHookError> {
        self.check_name(name)?;
        self.headers
            .retain(|header| !header.name().eq_ignore_ascii_case(name));
        Ok(())
    }

    fn check_name(&self, name: &str) -> Result<(), HeaderHookError> {
        if self
            .protected
            .iter()
            .any(|protected| protected.eq_ignore_ascii_case(name))
        {
            return Err(HeaderHookError::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "header is managed by the event source",
            )));
        }
        Ok(())
    }
}

impl fmt::Debug for HeaderHookContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderHookContext")
            .field("header_count", &self.headers.len())
            .finish_non_exhaustive()
    }
}

/// A hook failure. Formatting omits its cause, header names, and values.
///
/// Inspect [`Error::source`] to recover the original error. A failing hook
/// aborts the request before any connection is opened.
pub struct HeaderHookError(Box<dyn Error + Send + Sync>);

impl HeaderHookError {
    /// Wraps an error from your hook, such as a credential-provider failure.
    #[must_use]
    pub fn new(source: impl Error + Send + Sync + 'static) -> Self {
        Self(Box::new(source))
    }
}

impl fmt::Debug for HeaderHookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeaderHookError { .. }")
    }
}

impl fmt::Display for HeaderHookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("request header hook failed")
    }
}

impl Error for HeaderHookError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

fn validate(header: &RequestHeader) -> Result<(), HeaderHookError> {
    HeaderName::from_bytes(header.name().as_bytes()).map_err(HeaderHookError::new)?;
    HeaderValue::from_bytes(header.value()).map_err(HeaderHookError::new)?;
    Ok(())
}

type Callback = dyn Fn(&mut HeaderHookContext<'_>) -> Result<(), HeaderHookError> + Send + Sync;

#[derive(Clone)]
pub(crate) struct HeaderHook(Arc<Callback>);

impl HeaderHook {
    pub(crate) fn new<F>(hook: F) -> Self
    where
        F: Fn(&mut HeaderHookContext<'_>) -> Result<(), HeaderHookError> + Send + Sync + 'static,
    {
        Self(Arc::new(hook))
    }

    pub(crate) fn run(&self, context: &mut HeaderHookContext<'_>) -> Result<(), HeaderHookError> {
        (self.0)(context)
    }
}

impl fmt::Debug for HeaderHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeaderHook { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::{HeaderHookContext, HeaderHookError};
    use crate::RequestHeader;

    #[test]
    fn mutations_preserve_order_validate_before_change_and_redact_diagnostics()
    -> Result<(), Box<dyn std::error::Error>> {
        let method = http::Method::GET;
        let uri = "https://example.test/private?secret=canary".parse()?;
        let mut headers = vec![
            RequestHeader::new("X-First", "first"),
            RequestHeader::new("X-Token", "canary"),
            RequestHeader::new("x-token", "duplicate"),
            RequestHeader::new("X-Last", "last"),
        ];
        let mut context = HeaderHookContext {
            method: &method,
            uri: &uri,
            headers: &mut headers,
            protected: &["last-event-id"],
        };
        context.set(RequestHeader::new("X-TOKEN", "replacement").sensitive())?;
        assert_eq!(
            context
                .headers()
                .iter()
                .map(RequestHeader::name)
                .collect::<Vec<_>>(),
            ["X-First", "X-TOKEN", "X-Last"]
        );
        assert!(context.headers()[1].is_sensitive());
        let before = context.headers().to_vec();
        assert!(
            context
                .append(RequestHeader::new("bad name", "value"))
                .is_err()
        );
        assert!(
            context
                .set(RequestHeader::new("x-token", "bad\r\nvalue"))
                .is_err()
        );
        assert!(
            context
                .set(RequestHeader::new("Last-Event-ID", "value"))
                .is_err()
        );
        assert!(context.remove("LAST-EVENT-ID").is_err());
        assert_eq!(context.headers(), before);
        assert!(!format!("{context:?}").contains("canary"));
        context.remove("x-token")?;
        context.append(RequestHeader::new("X-Last", "duplicate"))?;
        assert_eq!(context.headers().len(), 3);
        let error = HeaderHookError::new(std::io::Error::other("private-canary"));
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert!(std::error::Error::source(&error).is_some());
        fn send_sync<T: Send + Sync + std::fmt::Debug>() {}
        send_sync::<HeaderHookContext<'static>>();
        send_sync::<HeaderHookError>();
        Ok(())
    }
}
