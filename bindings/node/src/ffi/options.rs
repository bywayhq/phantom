//! Typed client and request inputs normalized at the Node-API boundary.

use std::{fmt, time::Duration};

use napi::{
    Result,
    bindgen_prelude::{BigInt, Buffer, Reference},
};
use napi_derive::napi;

use super::{
    certificates::{ClientCertificateOrigin, NativeClientCertificate},
    prepared_body::NativePreparedBody,
};
use crate::error::failure;

/// One ordered request or response field, retaining arbitrary value bytes.
#[napi(object)]
pub struct WireHeader {
    /// Exact request spelling or received response spelling.
    pub name: String,
    /// Field value bytes.
    pub value: Buffer,
    /// Marks a caller field sensitive for compression and diagnostics.
    pub sensitive: Option<bool>,
}

/// Explicit native client configuration.
#[napi(object)]
pub struct ClientOptions {
    /// Exact compiled catalog identifier, unless an owned profile is supplied.
    pub profile: Option<String>,
    /// Either direct or proxy.
    pub route: String,
    /// Explicit HTTP, HTTPS, SOCKS4(a) or SOCKS5(h) proxy URI.
    pub proxy: Option<String>,
    /// Explicit proxy username, supplied together with proxyPassword.
    pub proxy_username: Option<String>,
    /// Explicit proxy password, never included in errors.
    pub proxy_password: Option<String>,
    /// SOCKS4 identification string; no password negotiation is supported.
    pub proxy_user_id: Option<String>,
    /// Enables the native cookie jar.
    pub cookies: Option<bool>,
    /// Maximum concurrent requests and unfinished bodies, from 1 to 1024.
    pub maximum_active_requests: Option<u32>,
    /// Additional DER trust roots, copied during construction.
    pub additional_roots: Option<Vec<Buffer>>,
    /// Additional trust roots for HTTPS proxy connections.
    pub additional_proxy_roots: Option<Vec<Buffer>>,
    /// Raw SHA-256 digests of accepted origin leaf DER SubjectPublicKeyInfo.
    pub server_spki_pins: Option<Vec<Buffer>>,
    /// Independent raw leaf SPKI digests for HTTPS proxy connections.
    pub proxy_server_spki_pins: Option<Vec<Buffer>>,
    /// Parsed default TLS client identity.
    pub client_certificate: Option<Reference<NativeClientCertificate>>,
    /// Ordered per-origin overrides; canonicalization belongs to the core.
    pub client_certificates_for: Option<Vec<ClientCertificateOrigin>>,
    /// Base HTTP(S) URL for relative request targets.
    pub base_url: Option<String>,
    /// Per-phase defaults; omitted phases retain the Rust defaults.
    pub timeouts: Option<PhaseTimeouts>,
    /// Default redirect following; omission leaves redirects visible.
    pub redirect_policy: Option<RedirectPolicyOptions>,
    /// Caller-enabled retry classes and scheduling; absence keeps them disabled.
    pub retry_policy: Option<RetryPolicyOptions>,
    /// Ordered local resolution overrides and source socket selection.
    pub network: Option<NetworkOptions>,
    /// Optional core pool retention, admission and setup-wait overrides.
    pub pool: Option<PoolOptions>,
}

/// Pool overrides; omitted fields retain the core or profile setting.
#[derive(Clone, Debug, Default)]
#[napi(object)]
pub struct PoolOptions {
    /// Retained HTTP/1.1 pool entries, not total live sockets.
    pub max_retained_http1_connections: Option<f64>,
    /// Active HTTP/1.1 requests per origin and route.
    pub max_concurrent_http1_requests_per_origin: Option<f64>,
    /// Waiting HTTP/1.1 requests per origin and route.
    pub max_pending_http1_requests_per_origin: Option<f64>,
    /// Retained HTTP/2 pool entries.
    pub max_retained_http2_connections: Option<f64>,
    /// Active HTTP/2 requests across a pool key's connections.
    pub max_concurrent_http2_requests_per_origin: Option<f64>,
    /// Waiting HTTP/2 requests per origin and route.
    pub max_pending_http2_requests_per_origin: Option<f64>,
    /// Maximum HTTP/2 connections per origin and route.
    pub max_http2_connections_per_origin: Option<f64>,
    /// Retained HTTP/3 pool entries.
    pub max_retained_http3_connections: Option<f64>,
    /// Active HTTP/3 requests across a pool key's connections.
    pub max_concurrent_http3_requests_per_origin: Option<f64>,
    /// Waiting HTTP/3 requests per origin and route.
    pub max_pending_http3_requests_per_origin: Option<f64>,
    /// Maximum QUIC connections per transport location; the core caps this at 8.
    pub max_http3_connections_per_origin: Option<f64>,
    /// Milliseconds before starting another negotiated TLS setup; zero is valid.
    pub negotiated_setup_wait_limit_ms: Option<f64>,
}

/// One logical hostname's ordered replacement addresses.
#[derive(Debug)]
#[napi(object)]
pub struct HostOverrideOptions {
    /// A domain name; core URL normalization and validation apply.
    pub host: String,
    /// Unscoped IP literals; an empty list intentionally fails local resolution.
    pub addresses: Vec<String>,
}

/// Optional client network configuration, independent of the browser profile.
#[napi(object)]
pub struct NetworkOptions {
    /// Ordered overrides; the last canonical matching hostname wins.
    pub host_overrides: Option<Vec<HostOverrideOptions>>,
    /// Ordered source IPs; the last address of each family wins.
    pub local_addresses: Option<Vec<String>>,
    /// OS interface name, validated and applied by the core.
    pub interface: Option<String>,
    /// Fixed UTF-8 Unix socket path; omitted from Debug output.
    pub unix_socket: Option<String>,
}

impl std::fmt::Debug for NetworkOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkOptions")
            .field("host_overrides", &self.host_overrides)
            .field("local_addresses", &self.local_addresses)
            .field("interface", &self.interface)
            .field("unix_socket_configured", &self.unix_socket.is_some())
            .finish()
    }
}

/// Native state categories selected by the JavaScript facade.
#[derive(Clone, Copy, Debug, Default)]
#[napi(object)]
pub struct SessionSharingOptions {
    /// Shares an already enabled cookie jar.
    pub cookies: Option<bool>,
    /// Shares the address cache and in-flight lookups.
    pub dns: Option<bool>,
    /// Shares learned client-hint preferences.
    pub client_hints: Option<bool>,
    /// Shares enabled discovery state and racing history.
    pub discovery: Option<bool>,
    /// Shares live, single-use TLS ticket stores.
    pub tickets: Option<bool>,
}

/// Explicit receiving ticket route; it does not change later request routing.
#[napi(object)]
pub struct SessionRouteOptions {
    /// Either direct or proxy.
    pub route: String,
    /// Explicit HTTP, HTTPS, SOCKS4(a) or SOCKS5(h) proxy URI.
    pub proxy: Option<String>,
    /// Optional paired proxy username.
    pub proxy_username: Option<String>,
    /// Optional paired proxy password, omitted from formatting.
    pub proxy_password: Option<String>,
    /// Optional SOCKS4 identification string, omitted from formatting.
    pub proxy_user_id: Option<String>,
}

impl fmt::Debug for SessionRouteOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRouteOptions")
            .finish_non_exhaustive()
    }
}

/// One normalized, private timeout choice from the JavaScript facade.
#[derive(Clone, Debug)]
#[napi(object)]
pub struct PhaseTimeout {
    /// Explicitly disables this phase instead of inheriting it.
    pub disabled: bool,
    /// Finite milliseconds, including zero; zero when disabled.
    pub milliseconds: u32,
}

/// Independent timeout choices for the five native request phases.
#[derive(Clone, Debug, Default)]
#[napi(object)]
pub struct PhaseTimeouts {
    /// Waiting for a native pool admission.
    pub pool_admission: Option<PhaseTimeout>,
    /// DNS, proxy negotiation, transport and TLS setup.
    pub connect: Option<PhaseTimeout>,
    /// Sending the request and receiving its final headers.
    pub response_head: Option<PhaseTimeout>,
    /// Inactivity between received body frames.
    pub read_idle: Option<PhaseTimeout>,
    /// The entire logical request through body completion.
    pub total: Option<PhaseTimeout>,
}

impl PhaseTimeouts {
    pub(crate) fn overrides(self) -> Result<phantom::RequestTimeoutOverrides> {
        fn phase(value: Option<PhaseTimeout>) -> Result<phantom::TimeoutOverride> {
            match value {
                None => Ok(phantom::TimeoutOverride::Inherit),
                Some(PhaseTimeout {
                    disabled: true,
                    milliseconds: 0,
                }) => Ok(phantom::TimeoutOverride::Disabled),
                Some(PhaseTimeout {
                    disabled: false,
                    milliseconds,
                }) => Ok(phantom::TimeoutOverride::Limit(Duration::from_millis(
                    u64::from(milliseconds),
                ))),
                Some(_) => Err(failure(
                    "InvalidTimeout",
                    "disabled phases must have no finite limit",
                )),
            }
        }
        Ok(phantom::RequestTimeoutOverrides::new()
            .pool_admission(phase(self.pool_admission)?)
            .connect(phase(self.connect)?)
            .response_head(phase(self.response_head)?)
            .read_idle(phase(self.read_idle)?)
            .total(phase(self.total)?))
    }
}

/// One bounded, one-shot regular-file upload.
#[napi(object)]
pub struct FileUpload {
    /// Local UTF-8 path.
    pub path: String,
    /// Refuses a file whose initial metadata length exceeds this limit.
    pub maximum_bytes: u32,
}

/// Request-only, opt-in decoding of advertised content codings.
#[derive(Debug)]
#[napi(object)]
pub struct ContentDecodingOptions {
    /// Either none or advertised; never adds Accept-Encoding.
    pub mode: String,
    /// Inclusive decoded-byte cap, including zero, for advertised decoding.
    pub maximum_decoded_bytes: Option<BigInt>,
}

impl ContentDecodingOptions {
    pub(crate) fn policy(self) -> Result<phantom::ContentDecoding> {
        match (self.mode.as_str(), self.maximum_decoded_bytes) {
            ("none", None) => Ok(phantom::ContentDecoding::none()),
            ("advertised", Some(value)) => match (value.sign_bit, value.words.as_slice()) {
                (false, [maximum]) => Ok(phantom::ContentDecoding::advertised(*maximum)),
                _ => Err(failure("InvalidArgument", "decoded-byte cap must fit u64")),
            },
            _ => Err(failure(
                "InvalidArgument",
                "invalid content-decoding policy",
            )),
        }
    }
}

/// Explicit redirect following, normalized before asynchronous work.
#[derive(Debug)]
#[napi(object)]
pub struct RedirectPolicyOptions {
    /// Either none or limited.
    pub mode: String,
    /// Positive hop bound for limited following.
    pub maximum_hops: Option<BigInt>,
}

pub(crate) fn positive_count(value: BigInt) -> Result<std::num::NonZeroUsize> {
    std::num::NonZeroUsize::new(policy_count(value)?)
        .ok_or_else(|| failure("InvalidArgument", "count must be positive"))
}

pub(crate) fn policy_count(value: BigInt) -> Result<usize> {
    match (value.sign_bit, value.words.as_slice()) {
        (false, [value]) => {
            usize::try_from(*value).map_err(|_| failure("InvalidArgument", "count must fit usize"))
        }
        _ => Err(failure("InvalidArgument", "count must fit usize")),
    }
}

impl RedirectPolicyOptions {
    pub(crate) fn policy(self) -> Result<phantom::RedirectPolicy> {
        match (self.mode.as_str(), self.maximum_hops) {
            ("none", None) => Ok(phantom::RedirectPolicy::none()),
            ("limited", Some(maximum)) => {
                Ok(phantom::RedirectPolicy::limited(positive_count(maximum)?))
            }
            _ => Err(failure("InvalidArgument", "invalid redirect policy")),
        }
    }
}

/// Bounded eligible connection-establishment retries and their scheduling.
#[derive(Debug)]
#[napi(object)]
pub struct ConnectionRetryOptions {
    /// Positive number of retries.
    pub maximum: BigInt,
    /// Initial finite nonnegative delay in milliseconds.
    pub delay_ms: f64,
    /// Optional exponential backoff cap, at least the initial delay.
    pub maximum_delay_ms: Option<f64>,
    /// Randomizes each delay within its configured bound.
    pub full_jitter: Option<bool>,
}

/// Explicit caller-listed response retries, subject to core replay rules.
#[derive(Debug)]
#[napi(object)]
pub struct StatusRetryOptions {
    /// HTTP status codes; the core validates retry eligibility.
    pub statuses: Vec<u32>,
    /// Positive retry count, shared across redirect hops.
    pub maximum: BigInt,
    /// Initial finite nonnegative delay in milliseconds.
    pub delay_ms: f64,
    /// Optional exponential backoff cap, at least the initial delay.
    pub maximum_delay_ms: Option<f64>,
    /// Randomizes the configured delay, not an honored Retry-After minimum.
    pub full_jitter: Option<bool>,
    /// Largest accepted server Retry-After delay, in milliseconds.
    pub retry_after_limit_ms: Option<f64>,
}

/// Whole caller retry policy; an empty object disables every caller class.
#[derive(Debug)]
#[napi(object)]
pub struct RetryPolicyOptions {
    /// Eligible failures before origin request dispatch.
    pub connection_failures: Option<ConnectionRetryOptions>,
    /// Safe replay after an already reused connection closes.
    pub reused_connection_replay: Option<bool>,
    /// Positive peer-unprocessed replay allowance.
    pub unprocessed_replays: Option<BigInt>,
    /// Explicit idempotent response-status retries.
    pub status_retry: Option<StatusRetryOptions>,
    /// Shared caller cap; zero disables caller retries.
    pub maximum_retries: Option<BigInt>,
    /// Explicitly permits failed exact HTTP/3 setup to try HTTP/2.
    pub http2_fallback: Option<bool>,
}

/// Owned inputs for one request.
#[napi(object)]
pub struct RequestOptions {
    /// Absolute HTTP/HTTPS URL, or a relative reference with a configured base.
    pub url: String,
    /// Explicit HTTP method.
    pub method: String,
    /// Exact http1/http2/http3, or explicitly negotiated HTTP/2 and HTTP/1.
    pub protocol: String,
    /// Explicit raw, attached profile template or compiled catalog context.
    pub context: String,
    /// Ordered duplicate fields.
    pub headers: Option<Vec<WireHeader>>,
    /// Ordered static fields emitted after successful body completion.
    pub trailers: Option<Vec<WireHeader>>,
    /// Optional nonnegative wait before sending a body without 100 Continue.
    pub expect_continue_ms: Option<BigInt>,
    /// Replayable byte upload, limited to 16 MiB.
    pub body: Option<Buffer>,
    /// Native-owned encoded bytes; mutually exclusive with all other bodies.
    pub prepared_body: Option<Reference<NativePreparedBody>>,
    /// One-shot file upload instead of bytes.
    pub file: Option<FileUpload>,
    /// Total deadline from submission, including file opening and body reads.
    pub timeout_ms: Option<u32>,
    /// Per-phase overrides; absence inherits and explicit disable removes a limit.
    pub timeouts: Option<PhaseTimeouts>,
    /// Decodes only caller-advertised codings, with an explicit byte cap.
    pub content_decoding: Option<ContentDecodingOptions>,
    /// Overrides the client policy; absence inherits it.
    pub redirect_policy: Option<RedirectPolicyOptions>,
    /// Positive number of selected hops to retain; does not enable following.
    pub redirect_history_limit: Option<BigInt>,
    /// Whole replacement for the client retry policy; absence inherits.
    pub retry_policy: Option<RetryPolicyOptions>,
}

impl fmt::Debug for WireHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("WireHeader").finish_non_exhaustive()
    }
}

impl fmt::Debug for ClientOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientOptions")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for FileUpload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FileUpload").finish_non_exhaustive()
    }
}

impl fmt::Debug for RequestOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestOptions")
            .finish_non_exhaustive()
    }
}
