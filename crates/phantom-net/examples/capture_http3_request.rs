//! Sends Phantom's Chrome 152 HTTP/3 request to the loopback capture server.
//!
//! The server owns packet decryption and fixture output. This client only
//! supplies the profiled TLS, QUIC transport, HTTP/3 settings, and request
//! shape.

use std::{env, error::Error, fs, net::SocketAddr, path::PathBuf, time::Duration};

use btls::x509::X509;
use http_body_util::BodyExt as _;
use phantom_net::http3::{Http3Connector, OriginForm, RequestHeader};
use phantom_profile::{CipherSuite, SignatureScheme, TlsSettings, TlsVersion, chromium};
use tokio::time::timeout;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
type CaptureResult<T> = Result<T, Box<dyn Error>>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> CaptureResult<()> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    require_loopback(arguments.remote)?;

    let certificate = X509::from_pem(&fs::read(&arguments.trust_root)?)?.to_der()?;
    let tls = capture_tls_settings();
    let connector = Http3Connector::new_with_additional_roots(
        &tls,
        &chromium::v152_macos_quic(),
        &chromium::v152_macos_http3(),
        &chromium::v152_macos_http3_request(),
        std::iter::once(certificate.as_slice()),
    )?;

    let authority = format!("{}:{}", arguments.hostname, arguments.remote.port());
    let response = timeout(
        REQUEST_TIMEOUT,
        connector.send_get_direct(
            &arguments.remote.ip().to_string(),
            arguments.remote.port(),
            &arguments.hostname,
            &authority,
            OriginForm::parse("/")?,
            chrome_request_headers(),
        ),
    )
    .await
    .map_err(|_| "HTTP/3 capture request timed out")??;

    if response.status() != 200 {
        return Err(format!("capture server returned {}", response.status()).into());
    }
    let body = timeout(REQUEST_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| "HTTP/3 response body timed out")??
        .to_bytes();
    if body.as_ref() != b"ok" {
        return Err("capture server returned an unexpected body".into());
    }
    Ok(())
}

fn capture_tls_settings() -> TlsSettings {
    let mut settings = chromium::v152_macos_tls();
    settings.min_version = TlsVersion::Tls13;
    settings.max_version = TlsVersion::Tls13;
    settings.cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::Chacha20Poly1305Sha256,
    ];
    settings.signature_schemes = vec![
        SignatureScheme::EcdsaSecp256r1Sha256,
        SignatureScheme::RsaPssRsaeSha256,
        SignatureScheme::RsaPkcs1Sha256,
        SignatureScheme::EcdsaSecp384r1Sha384,
        SignatureScheme::RsaPssRsaeSha384,
        SignatureScheme::RsaPkcs1Sha384,
        SignatureScheme::RsaPssRsaeSha512,
        SignatureScheme::RsaPkcs1Sha512,
        SignatureScheme::RsaPkcs1Sha1,
    ];
    settings.alpn_protocols = vec![Box::from(&b"h3"[..])];
    settings.alps = None;
    settings.session_tickets = false;
    settings.grease = false;
    settings.grease_signature_algorithms = false;
    settings.request_ocsp_staple = false;
    settings.request_signed_certificate_timestamps = false;
    settings
}

struct Arguments {
    remote: SocketAddr,
    hostname: String,
    trust_root: PathBuf,
}

impl Arguments {
    fn parse(mut values: impl Iterator<Item = String>) -> CaptureResult<Self> {
        let usage = concat!(
            "usage: capture_http3_request <loopback-address:port> ",
            "<hostname> <trust-root-pem>"
        );
        let remote = values.next().ok_or(usage)?.parse()?;
        let hostname = values.next().ok_or(usage)?;
        let trust_root = values.next().ok_or(usage)?.into();
        if values.next().is_some() || hostname.is_empty() || hostname.contains(['\r', '\n']) {
            return Err(usage.into());
        }
        Ok(Self {
            remote,
            hostname,
            trust_root,
        })
    }
}

fn require_loopback(remote: SocketAddr) -> CaptureResult<()> {
    if !remote.ip().is_loopback() {
        return Err(format!("capture server must be loopback, received {remote}").into());
    }
    Ok(())
}

fn chrome_request_headers() -> Vec<RequestHeader> {
    vec![
        RequestHeader::new(
            "sec-ch-ua",
            r#""Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152""#,
        ),
        RequestHeader::new("sec-ch-ua-mobile", "?0"),
        RequestHeader::new("sec-ch-ua-platform", r#""macOS""#),
        RequestHeader::new("upgrade-insecure-requests", "1"),
        RequestHeader::new(
            "user-agent",
            concat!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
                "AppleWebKit/537.36 (KHTML, like Gecko) ",
                "HeadlessChrome/152.0.0.0 Safari/537.36"
            ),
        ),
        RequestHeader::new(
            "accept",
            concat!(
                "text/html,application/xhtml+xml,application/xml;q=0.9,",
                "image/avif,image/webp,image/apng,*/*;q=0.8,",
                "application/signed-exchange;v=b3;q=0.7"
            ),
        ),
        RequestHeader::new("sec-fetch-site", "none"),
        RequestHeader::new("sec-fetch-mode", "navigate"),
        RequestHeader::new("sec-fetch-user", "?1"),
        RequestHeader::new("sec-fetch-dest", "document"),
        RequestHeader::new("accept-encoding", "gzip, deflate, br, zstd"),
        RequestHeader::new("accept-language", "en-US,en;q=0.9"),
        RequestHeader::new("priority", "u=0, i"),
    ]
}

#[cfg(test)]
mod tests {
    use super::{Arguments, chrome_request_headers, require_loopback};

    #[test]
    fn arguments_are_exact_and_hostname_is_one_line() {
        let valid = Arguments::parse(
            ["127.0.0.1:9447", "server.phantom.test", "root.pem"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(valid.is_ok());

        for values in [
            vec!["127.0.0.1:9447", "server.phantom.test"],
            vec!["127.0.0.1:9447", "server.phantom.test", "root.pem", "extra"],
            vec!["127.0.0.1:9447", "server.phantom.test\nother", "root.pem"],
        ] {
            assert!(Arguments::parse(values.into_iter().map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn capture_target_must_be_loopback() -> Result<(), Box<dyn std::error::Error>> {
        assert!(require_loopback("127.0.0.1:9447".parse()?).is_ok());
        assert!(require_loopback("[::1]:9447".parse()?).is_ok());
        assert!(require_loopback("192.0.2.1:9447".parse()?).is_err());
        Ok(())
    }

    #[test]
    fn request_headers_match_the_capture_boundary() {
        let headers = chrome_request_headers();
        assert_eq!(headers.len(), 13);
        assert_eq!(
            headers.first().map(|header| header.name()),
            Some("sec-ch-ua")
        );
        assert_eq!(headers.last().map(|header| header.name()), Some("priority"));
        assert!(
            headers
                .iter()
                .all(|header| header.name() == header.name().to_ascii_lowercase())
        );
    }
}
