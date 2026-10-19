use std::{fmt, num::NonZeroUsize, sync::Arc};

use http::{Method, StatusCode};
use phantom_net::request::RequestHeader;
use phantom_profile::ClientHintSettings;
use url::Url;

use crate::{RequestError, request::RequestBodySource};

mod history;
pub use history::{RedirectHistory, RedirectHop};

/// Client policy for following HTTP redirects.
///
/// The default, equal to [`RedirectPolicy::none`], returns every redirect
/// response to the caller. Set the policy for a whole client with
/// [`ClientBuilder::redirect_policy`](crate::ClientBuilder::redirect_policy),
/// or replace it for one request with
/// [`RequestBuilder::redirect_policy`](crate::RequestBuilder::redirect_policy).
/// Use [`RedirectPolicy::custom`] to decide which resolved URLs to follow.
/// Cloning a policy shares its callback. Callbacks may carry state and are not
/// required to be unwind safe.
///
/// A 301, 302, 303, 307, or 308 is followed to an `http://` or `https://`
/// target; any other resolved `Location` scheme fails with
/// [`RequestErrorKind::Redirect`](crate::RequestErrorKind::Redirect). A
/// redirect without `Location` is returned unchanged. More than one
/// `Location`, a location that does not resolve, or a hop past the limit
/// also fails with that kind, and the redirect response is not returned.
///
/// Each hop keeps the request's explicit route overrides and protocol rule,
/// its total timeout, and its retry budget. Environment routing selects a
/// route for each new logical origin, as [`crate::EnvironmentProxies`] describes.
/// An unsupported hop fails before it is sent, with the same typed error
/// the first request would get. A 307 or 308 resends
/// the method and body; a one-shot streaming body cannot be resent and fails
/// with [`RequestErrorKind::RequestBody`](crate::RequestErrorKind::RequestBody).
/// A cross-origin hop, including a change between `http://` and `https://`,
/// removes `Authorization`, `Cookie`, `Cookie2`, and `Proxy-Authorization`
/// fields and trailers, including the fields a request template sends
/// itself, from that hop and every later one.
///
/// # Examples
///
/// ```
/// use std::num::NonZeroUsize;
///
/// use phantom::profile::{browser::chrome, ClientProfile};
/// use phantom::{Client, RedirectPolicy};
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let policy = RedirectPolicy::limited(NonZeroUsize::new(5).expect("five is nonzero"));
/// let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http2(chrome::v154_http2());
/// let client = Client::builder(profile).redirect_policy(policy).build()?;
/// # drop(client);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default)]
pub struct RedirectPolicy {
    maximum: Option<NonZeroUsize>,
    callback: Option<Arc<RedirectCallback>>,
}

type RedirectCallback = dyn Fn(&RedirectAttempt<'_>) -> RedirectDecision + Send + Sync;

impl fmt::Debug for RedirectPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedirectPolicy")
            .field("maximum", &self.maximum)
            .field("custom", &self.callback.is_some())
            .finish()
    }
}

/// What to do with a proposed redirect hop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RedirectDecision {
    /// Follow the hop using the existing replay and credential rules.
    Follow,
    /// Return this redirect response, including its unread body.
    Stop,
    /// Fail with [`RequestErrorKind::Redirect`](crate::RequestErrorKind::Redirect).
    Reject,
}

/// A redirect target after resolving `Location` against the current URL.
///
/// The callback borrows this value before sending the next hop. URLs may contain
/// credentials or sensitive paths and queries, so debug output omits them.
/// This describes a URL, not DNS results or a connected IP address.
#[derive(Clone, Copy)]
pub struct RedirectAttempt<'a> {
    from: &'a Url,
    to: &'a Url,
    status: StatusCode,
    method: &'a Method,
    next_method: &'a Method,
    hop: usize,
}

impl RedirectAttempt<'_> {
    /// Returns the URL that produced the redirect response.
    #[must_use]
    pub const fn from_url(&self) -> &Url {
        self.from
    }

    /// Returns the resolved destination URL.
    #[must_use]
    pub const fn to_url(&self) -> &Url {
        self.to
    }

    /// Returns the redirect response's status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the method that produced the redirect response.
    #[must_use]
    pub const fn method(&self) -> &Method {
        self.method
    }

    /// Returns the method that following the redirect would send.
    #[must_use]
    pub const fn next_method(&self) -> &Method {
        self.next_method
    }

    /// Returns the proposed hop number, starting at one.
    #[must_use]
    pub const fn hop(&self) -> usize {
        self.hop
    }
}

impl fmt::Debug for RedirectAttempt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedirectAttempt")
            .field("status", &self.status)
            .field("method", &self.method)
            .field("next_method", &self.next_method)
            .field("hop", &self.hop)
            .finish_non_exhaustive()
    }
}

impl RedirectPolicy {
    /// Leaves redirect responses visible to the caller.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            maximum: None,
            callback: None,
        }
    }

    /// Follows at most `maximum` redirect responses per request.
    ///
    /// A redirect that would exceed `maximum` fails with
    /// [`RequestErrorKind::Redirect`](crate::RequestErrorKind::Redirect).
    #[must_use]
    pub const fn limited(maximum: NonZeroUsize) -> Self {
        Self {
            maximum: Some(maximum),
            callback: None,
        }
    }

    /// Consults `callback` before each hop, following at most `maximum` hops.
    ///
    /// The callback runs synchronously after resolving and validating `Location`.
    /// It can restrict destination URLs, stop with the original response, or
    /// reject the hop. It cannot override the hop limit, replay rules, total
    /// deadline or shared attempt budget. Keep callbacks short and nonblocking.
    /// Cloned policies share the callback, which can run concurrently.
    ///
    /// DNS and connection setup happen later. This callback does not enforce
    /// restrictions on resolved IP addresses.
    ///
    /// ```
    /// use std::num::NonZeroUsize;
    /// use phantom::{RedirectDecision, RedirectPolicy};
    ///
    /// let policy = RedirectPolicy::custom(NonZeroUsize::MIN, |attempt| {
    ///     if attempt.from_url().origin() == attempt.to_url().origin() {
    ///         RedirectDecision::Follow
    ///     } else {
    ///         RedirectDecision::Stop
    ///     }
    /// });
    /// ```
    #[must_use]
    pub fn custom(
        maximum: NonZeroUsize,
        callback: impl Fn(&RedirectAttempt<'_>) -> RedirectDecision + Send + Sync + 'static,
    ) -> Self {
        Self {
            maximum: Some(maximum),
            callback: Some(Arc::new(callback)),
        }
    }

    /// Returns the configured redirect limit, or `None` when following is disabled.
    #[must_use]
    pub const fn max_hops(&self) -> Option<NonZeroUsize> {
        self.maximum
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum RedirectAction {
    Stop,
    Follow { same_origin: bool },
}

pub(crate) struct RedirectState {
    policy: RedirectPolicy,
    current_url: Url,
    method: Method,
    headers: Vec<RequestHeader>,
    trailers: Vec<RequestHeader>,
    body: RequestBodySource,
    followed: usize,
}

impl RedirectState {
    pub(crate) fn new(
        policy: RedirectPolicy,
        current_url: Url,
        method: Method,
        headers: Vec<RequestHeader>,
        trailers: Vec<RequestHeader>,
        body: RequestBodySource,
    ) -> Self {
        Self {
            policy,
            current_url,
            method,
            headers,
            trailers,
            body,
            followed: 0,
        }
    }

    pub(crate) fn current_url(&self) -> &Url {
        &self.current_url
    }

    pub(crate) fn method(&self) -> &Method {
        &self.method
    }

    pub(crate) fn headers(&self) -> &[RequestHeader] {
        &self.headers
    }

    pub(crate) fn trailers(&self) -> &[RequestHeader] {
        &self.trailers
    }

    #[cfg(test)]
    pub(crate) fn body(&self) -> Option<&bytes::Bytes> {
        self.body.replayable_bytes()
    }

    pub(crate) fn body_mut(&mut self) -> &mut RequestBodySource {
        &mut self.body
    }

    pub(crate) fn followed(&self) -> usize {
        self.followed
    }

    pub(crate) fn strip_client_hints(&mut self, settings: &ClientHintSettings, managed: &[&str]) {
        self.headers.retain(|header| {
            crate::request::template::is_managed(managed, header.name())
                || !settings
                    .hints()
                    .iter()
                    .any(|hint| header.name().eq_ignore_ascii_case(hint.name()))
        });
    }

    pub(crate) fn follow<B>(
        &mut self,
        response: &http::Response<B>,
    ) -> Result<RedirectAction, RequestError> {
        if !is_redirect(response.status()) {
            return Ok(RedirectAction::Stop);
        }

        let Some(maximum) = self.policy.maximum else {
            return Ok(RedirectAction::Stop);
        };

        let mut locations = response.headers().get_all(http::header::LOCATION).iter();
        let Some(location) = locations.next() else {
            return Ok(RedirectAction::Stop);
        };

        if locations.next().is_some() {
            return Err(RequestError::ambiguous_redirect_location());
        }

        if self.followed >= maximum.get() {
            return Err(RequestError::redirect_limit());
        }

        let location = location
            .to_str()
            .map_err(RequestError::invalid_redirect_header)?;
        let next_url = self
            .current_url
            .join(location)
            .map_err(RequestError::invalid_redirect_url)?;
        if !matches!(next_url.scheme(), "http" | "https") {
            return Err(RequestError::redirect_scheme());
        }

        if let Some(callback) = &self.policy.callback {
            let next_method = if changes_to_get(response.status(), &self.method) {
                &Method::GET
            } else {
                &self.method
            };
            match callback(&RedirectAttempt {
                from: &self.current_url,
                to: &next_url,
                status: response.status(),
                method: &self.method,
                next_method,
                hop: self.followed + 1,
            }) {
                RedirectDecision::Follow => {}
                RedirectDecision::Stop => return Ok(RedirectAction::Stop),
                RedirectDecision::Reject => {
                    return Err(RequestError::invalid_redirect_target(
                        "redirect callback rejected the target",
                    ));
                }
            }
        }

        if changes_to_get(response.status(), &self.method) {
            self.method = Method::GET;
            self.body.clear();
            self.trailers.clear();
            self.headers.retain(|header| !is_body_header(header.name()));
        }
        let same_origin = self.current_url.origin() == next_url.origin();
        if !same_origin {
            self.headers
                .retain(|header| !is_credential_header(header.name()));
            self.trailers
                .retain(|header| !is_credential_header(header.name()));
        }

        self.current_url = next_url;
        self.followed += 1;
        Ok(RedirectAction::Follow { same_origin })
    }
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn changes_to_get(status: StatusCode, method: &Method) -> bool {
    match status {
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND => *method == Method::POST,
        StatusCode::SEE_OTHER => *method != Method::GET && *method != Method::HEAD,
        StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => false,
        _ => false,
    }
}

fn is_body_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-encoding")
        || name.eq_ignore_ascii_case("content-language")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("content-location")
        || name.eq_ignore_ascii_case("content-type")
        || name.eq_ignore_ascii_case("transfer-encoding")
}

/// Whether a field carries credentials that a cross-origin hop removes.
pub(crate) fn is_credential_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("cookie2")
        || name.eq_ignore_ascii_case("proxy-authorization")
}

#[cfg(test)]
mod tests;
