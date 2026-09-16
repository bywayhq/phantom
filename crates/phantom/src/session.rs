use std::{fmt, num::NonZeroUsize, sync::Arc};

use crate::{Client, HttpProtocol, RequestBuilder, RequestError};

#[cfg(feature = "cookies")]
mod cookies;
mod http2_pool;

#[cfg(feature = "cookies")]
pub use cookies::{CookieError, CookieErrorKind, CookieJar, CookieLimits};

const DEFAULT_MAX_RETAINED_HTTP2_CONNECTIONS: NonZeroUsize = match NonZeroUsize::new(32) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};

/// Cloneable cross-request state for one immutable [`Client`].
///
/// Clones share the same connection pool. Separate sessions never share
/// mutable state, even when they originate from the same client.
#[derive(Clone)]
pub struct Session {
    pub(crate) client: Client,
    pub(crate) state: Arc<SessionState>,
}

pub(crate) struct SessionState {
    pub(crate) http2: http2_pool::Http2Pool,
    #[cfg(feature = "cookies")]
    pub(crate) cookies: Option<Arc<CookieJar>>,
}

impl Session {
    /// Starts one empty-body GET using exactly `protocol`.
    ///
    /// HTTP/2 requests may reuse a compatible connection owned by this
    /// session. Other protocols retain the client's one-shot behavior.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] when the protocol is absent from the profile
    /// or the URI, authority, or request target is invalid.
    pub fn get(&self, protocol: HttpProtocol, uri: &str) -> Result<RequestBuilder, RequestError> {
        RequestBuilder::new_session(self.clone(), protocol, uri)
    }

    /// Returns this session's cookie jar when cookie handling was enabled.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookie_jar(&self) -> Option<&CookieJar> {
        self.state.cookies.as_deref()
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field(
                "max_retained_http2_connections",
                &self.state.http2.capacity(),
            )
            .field("cookies_enabled", &{
                #[cfg(feature = "cookies")]
                {
                    self.state.cookies.is_some()
                }
                #[cfg(not(feature = "cookies"))]
                {
                    false
                }
            })
            .finish_non_exhaustive()
    }
}

/// Builds one isolated [`Session`].
pub struct SessionBuilder {
    client: Client,
    max_retained_http2_connections: NonZeroUsize,
    #[cfg(feature = "cookies")]
    cookie_jar: Option<CookieJar>,
}

impl SessionBuilder {
    pub(crate) fn new(client: Client) -> Self {
        Self {
            client,
            max_retained_http2_connections: DEFAULT_MAX_RETAINED_HTTP2_CONNECTIONS,
            #[cfg(feature = "cookies")]
            cookie_jar: None,
        }
    }

    /// Sets the maximum number of HTTP/2 connections retained for reuse.
    ///
    /// Evicting a connection from the pool does not cancel response bodies
    /// already using it. It prevents later requests from selecting it.
    #[must_use]
    pub fn max_retained_http2_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.max_retained_http2_connections = maximum;
        self
    }

    /// Enables an isolated in-memory cookie jar with default bounds.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookies(mut self) -> Self {
        self.cookie_jar = Some(CookieJar::default());
        self
    }

    /// Enables cookie handling with a caller-created jar.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookie_jar(mut self, jar: CookieJar) -> Self {
        self.cookie_jar = Some(jar);
        self
    }

    /// Builds the session.
    #[must_use]
    pub fn build(self) -> Session {
        Session {
            client: self.client,
            state: Arc::new(SessionState {
                http2: http2_pool::Http2Pool::new(self.max_retained_http2_connections),
                #[cfg(feature = "cookies")]
                cookies: self.cookie_jar.map(Arc::new),
            }),
        }
    }
}

impl fmt::Debug for SessionBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionBuilder")
            .field(
                "max_retained_http2_connections",
                &self.max_retained_http2_connections,
            )
            .field("cookies_enabled", &{
                #[cfg(feature = "cookies")]
                {
                    self.cookie_jar.is_some()
                }
                #[cfg(not(feature = "cookies"))]
                {
                    false
                }
            })
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{Session, SessionBuilder};
    use crate::RequestBuilder;

    fn assert_send_sync_clone<T: Send + Sync + Clone>() {}

    #[test]
    fn session_handles_are_send_sync_and_clone() {
        assert_send_sync_clone::<Session>();
        fn assert_send<T: Send>() {}
        assert_send::<SessionBuilder>();
        fn assert_send_static<T: Send + 'static>() {}
        assert_send_static::<RequestBuilder>();
        #[cfg(feature = "cookies")]
        assert_send_sync::<super::CookieJar>();
    }

    #[cfg(feature = "cookies")]
    fn assert_send_sync<T: Send + Sync>() {}
}
