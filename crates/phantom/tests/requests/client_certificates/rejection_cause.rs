use std::net::Ipv4Addr;

use btls::ssl::ErrorCode;
use phantom::{RequestError, RequestErrorKind, profile::TlsVersion};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};

use super::{
    ClientIdentity, TEST_TIMEOUT, TestIdentity, TestResult, acceptor, client, get, http3_client,
    quic_endpoint_requiring, quic_missing_certificate_rejected, serve_one, serve_one_http3,
    tcp_missing_certificate_rejected, tls,
};

// The retained native headers define these SSL library and reason constants.
const ERR_LIB_SSL: i32 = 16;
const SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE: i32 = 192;
const SSL_R_CERTIFICATE_VERIFY_FAILED: i32 = 125;

#[tokio::test]
async fn required_tcp_certificate_has_a_missing_certificate_cause() -> TestResult<()> {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let (served, error) = tcp_rejection(version, CertificateInput::Missing).await?;

        assert!(tcp_reason(&served, SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE));
        assert!(!tcp_reason(&served, SSL_R_CERTIFICATE_VERIFY_FAILED));
        assert!(tcp_missing_certificate_rejected(
            &served,
            &error,
            expected_tcp_categories(version)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn tls12_rejection_of_a_presented_certificate_does_not_prove_one_is_missing() -> TestResult<()>
{
    reject_wrong_tcp_certificate(TlsVersion::Tls12).await
}

#[tokio::test]
async fn tls13_rejection_of_a_presented_certificate_does_not_prove_one_is_missing() -> TestResult<()>
{
    reject_wrong_tcp_certificate(TlsVersion::Tls13).await
}

#[tokio::test]
async fn required_quic_certificate_has_a_certificate_required_cause() -> TestResult<()> {
    let (served, error) = quic_rejection(CertificateInput::Missing).await?;

    assert!(quic_alert(
        &served,
        rustls::AlertDescription::CertificateRequired
    ));
    assert!(!quic_alert(&served, rustls::AlertDescription::UnknownCA));
    assert!(quic_missing_certificate_rejected(&served, &error));
    Ok(())
}

#[tokio::test]
async fn quic_rejection_of_a_presented_certificate_does_not_prove_one_is_missing() -> TestResult<()>
{
    let (served, error) = quic_rejection(CertificateInput::WrongAuthority).await?;

    assert!(quic_alert(&served, rustls::AlertDescription::UnknownCA));
    assert!(!quic_alert(
        &served,
        rustls::AlertDescription::CertificateRequired
    ));
    assert!(matches!(
        error.kind(),
        RequestErrorKind::Tls | RequestErrorKind::Http3
    ));

    assert!(
        !quic_missing_certificate_rejected(&served, &error),
        "QUIC missing-certificate observer accepted a certificate verification failure"
    );
    Ok(())
}

enum CertificateInput {
    Missing,
    WrongAuthority,
}

async fn reject_wrong_tcp_certificate(version: TlsVersion) -> TestResult<()> {
    let (served, error) = tcp_rejection(version, CertificateInput::WrongAuthority).await?;

    assert!(tcp_reason(&served, SSL_R_CERTIFICATE_VERIFY_FAILED));
    assert!(!tcp_reason(
        &served,
        SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE
    ));
    assert!(expected_tcp_categories(version).contains(&error.kind()));

    assert!(
        !tcp_missing_certificate_rejected(&served, &error, expected_tcp_categories(version)),
        "TCP missing-certificate observer accepted a certificate verification failure"
    );
    Ok(())
}

async fn tcp_rejection(
    version: TlsVersion,
    input: CertificateInput,
) -> TestResult<(TestResult<Option<Vec<u8>>>, RequestError)> {
    let server = TestIdentity::generate()?;
    let authority = ClientIdentity::p256()?;
    let certificate = match input {
        CertificateInput::Missing => None,
        CertificateInput::WrongAuthority => Some(ClientIdentity::p256()?.certificate()?),
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = acceptor(&server, Some(&authority.authority_der))?;
    let client = client(&server, tls(version), certificate)?;

    let (served, requested) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            serve_one(listener, acceptor),
            get(&client, format!("https://{address}/"))
        )
    })
    .await?;
    let error = requested
        .err()
        .ok_or("controlled TCP rejection accepted the request")?;

    Ok((served, error))
}

async fn quic_rejection(
    input: CertificateInput,
) -> TestResult<(TestResult<Option<Vec<u8>>>, RequestError)> {
    let server = TestIdentity::generate()?;
    let authority = ClientIdentity::p256()?;
    let certificate = match input {
        CertificateInput::Missing => None,
        CertificateInput::WrongAuthority => Some(ClientIdentity::p256()?.certificate()?),
    };
    let (address, endpoint) = quic_endpoint_requiring(&server, &authority.authority_der)?;
    let client = http3_client(&server, certificate)?;
    let (_done, done_received) = oneshot::channel();

    let (served, requested) = timeout(TEST_TIMEOUT, async {
        tokio::join!(serve_one_http3(&endpoint, done_received), async {
            client
                .get(phantom::HttpProtocol::Http3, &format!("https://{address}/"))?
                .send()
                .await
        })
    })
    .await?;
    let error = requested
        .err()
        .ok_or("controlled QUIC rejection accepted the request")?;

    Ok((served, error))
}

fn expected_tcp_categories(version: TlsVersion) -> &'static [RequestErrorKind] {
    if version == TlsVersion::Tls13 {
        &[RequestErrorKind::Tls, RequestErrorKind::Http1]
    } else {
        &[RequestErrorKind::Tls, RequestErrorKind::Tls]
    }
}

fn tcp_reason(served: &TestResult<Option<Vec<u8>>>, reason: i32) -> bool {
    let Err(error) = served else {
        return false;
    };

    let Some(error) = error.downcast_ref::<btls::ssl::Error>() else {
        return false;
    };

    error.code() == ErrorCode::SSL
        && error.ssl_error().is_some_and(|stack| {
            stack
                .errors()
                .iter()
                .any(|error| error.library_code() == ERR_LIB_SSL && error.reason_code() == reason)
        })
}

fn quic_alert(served: &TestResult<Option<Vec<u8>>>, alert: rustls::AlertDescription) -> bool {
    let Err(error) = served else {
        return false;
    };

    matches!(
        error.downcast_ref::<quinn::ConnectionError>(),
        Some(quinn::ConnectionError::TransportError(error))
            if error.code == quinn::TransportErrorCode::crypto(u8::from(alert))
    )
}
