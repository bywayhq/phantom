use std::num::NonZeroUsize;

use bytes::Bytes;
use http::{Method, StatusCode};
use phantom_net::request::RequestHeader;
use phantom_profile::ClientHintSettings;
use url::Url;

use crate::RequestError;

/// Session policy for following HTTP redirects.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RedirectPolicy {
    maximum: Option<NonZeroUsize>,
}

impl RedirectPolicy {
    /// Leaves redirect responses visible to the caller.
    #[must_use]
    pub const fn none() -> Self {
        Self { maximum: None }
    }

    /// Follows at most `maximum` redirect responses per request.
    #[must_use]
    pub const fn limited(maximum: NonZeroUsize) -> Self {
        Self {
            maximum: Some(maximum),
        }
    }

    /// Returns the configured redirect limit, or `None` when following is disabled.
    #[must_use]
    pub const fn max_hops(self) -> Option<NonZeroUsize> {
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
    body: Option<Bytes>,
    followed: usize,
}

impl RedirectState {
    pub(crate) fn new(
        policy: RedirectPolicy,
        current_url: Url,
        method: Method,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Self {
        Self {
            policy,
            current_url,
            method,
            headers,
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

    pub(crate) fn body(&self) -> Option<&Bytes> {
        self.body.as_ref()
    }

    pub(crate) fn followed(&self) -> usize {
        self.followed
    }

    pub(crate) fn strip_client_hints(&mut self, settings: &ClientHintSettings) {
        self.headers.retain(|header| {
            !settings
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
        if next_url.scheme() != "https" {
            return Err(RequestError::redirect_scheme());
        }

        if changes_to_get(response.status(), &self.method) {
            self.method = Method::GET;
            self.body = None;
            self.headers.retain(|header| !is_body_header(header.name()));
        }
        let same_origin = self.current_url.origin() == next_url.origin();
        if !same_origin {
            self.headers
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

fn is_credential_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("cookie2")
        || name.eq_ignore_ascii_case("proxy-authorization")
}

#[cfg(test)]
#[path = "redirect/tests.rs"]
mod tests;
